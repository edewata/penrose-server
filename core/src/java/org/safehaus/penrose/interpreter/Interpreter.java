/**
 * Copyright 2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package org.safehaus.penrose.interpreter;

import org.safehaus.penrose.directory.EntryAttributeConfig;
import org.safehaus.penrose.directory.EntryFieldConfig;
import org.safehaus.penrose.directory.EntryField;
import org.safehaus.penrose.ldap.Attribute;
import org.safehaus.penrose.ldap.Attributes;
import org.safehaus.penrose.ldap.RDN;
import org.safehaus.penrose.ldap.SourceAttributes;
import org.safehaus.penrose.mapping.Expression;
import org.safehaus.penrose.mapping.MappingRule;
import org.safehaus.penrose.source.Field;
import org.safehaus.penrose.Penrose;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;

/**
 * @author Endi S. Dewata
 */
public abstract class Interpreter {

    public Logger log = LoggerFactory.getLogger(getClass());

    protected Collection rows;
    protected ClassLoader classLoader;

    public void set(RDN rdn) throws Exception {
        set(null, rdn);
    }

    public void set(String prefix, RDN rdn) throws Exception {
        if (rdn == null) return;
        
        for (String name : rdn.getNames()) {
            Object value = rdn.get(name);
            set(prefix == null ? name : prefix+"."+name, value);
        }
    }

    public void set(SourceAttributes sv) throws Exception {
        for (String sourceName : sv.getNames()) {
            Attributes attributes = sv.get(sourceName);

            for (String fieldName : attributes.getNames()) {
                Attribute attribute = attributes.get(fieldName);

                if (attribute.getSize() == 1) {
                    set(sourceName+"."+fieldName, attribute.getValue());
                } else {
                    set(sourceName+"."+fieldName, attribute.getValues());
                }
            }
        }
    }

    public void set(Attributes attributes) throws Exception {
        set(null, attributes);
    }

    public void set(String prefix, Attributes attributes) throws Exception {
        for (String name : attributes.getNames()) {
            Collection<Object> values = attributes.getValues(name);
            if (log.isDebugEnabled()) log.debug("Setting "+name+": "+values);

            Object value;
            if (values.size() == 1) {
                value = values.iterator().next();
            } else {
                Collection<Object> list = new ArrayList<Object>();
                list.addAll(values);
                value = list;
            }

            set(prefix == null ? name : prefix+"."+name, value);
        }
    }

    public abstract Collection<String> parseVariables(String script) throws Exception;

    public abstract void set(String name, Object value) throws Exception;

    public abstract Object get(String name) throws Exception;

    public abstract Object eval(String script) throws Exception;

    public abstract void clear() throws Exception;

    public Object eval(EntryAttributeConfig attributeMapping) throws Exception {
        try {
            Object constant = attributeMapping.getConstant();
            if (constant != null) {
                //log.debug("Constant: "+constant);
                return constant;
            }

            String variable = attributeMapping.getVariable();
            if (variable != null) {
                //log.debug("Variable: "+variable);
                return get(variable);
            }

            Expression expression = attributeMapping.getExpression();
            if (expression != null) {
                //log.debug("Expression: "+expression);
                return eval(expression);
            }

            //log.debug("Variable: "+attributeMapping.getName());
            return get(attributeMapping.getName());

        } catch (Exception e) {
            Penrose.errorLog.error("Error evaluating attribute "+attributeMapping.getName()+": "+e.getMessage());
            throw e;
        }
    }

    public Object eval(Field field) throws Exception {
        try {
            Object constant = field.getConstant();
            if (constant != null) {
                //log.debug("Constant: "+constant);
                return constant;
            }

            String variable = field.getVariable();
            if (variable != null) {
                Object value = get(variable);
                if (value == null && variable.startsWith("rdn.")) {
                    value = get(variable.substring(4));
                }
                //log.debug("Variable: "+variable+" = "+value);
                return value;

            }

            Expression expression = field.getExpression();
            if (expression != null) {
                Object value = eval(expression);
                //log.debug("Expression: "+expression+" = "+value);
                return value;

            }

            //log.debug("Undefined field.");
            return null;

        } catch (Exception e) {
            throw new Exception("Error evaluating field "+field.getName(), e);
        }
    }

    public Object eval(EntryField fieldRef) throws Exception {
        try {
            if (fieldRef.getConstant() != null) {
                return fieldRef.getConstant();

            } else if (fieldRef.getVariable() != null) {
                String name = fieldRef.getVariable();
                Object value = get(name);
                if (value == null && name.startsWith("rdn.")) {
                    value = get(name.substring(4));
                }
                return value;

            } else if (fieldRef.getExpression() != null) {
                return eval(fieldRef.getExpression());

            } else {
                return null;
            }
        } catch (Exception e) {
            throw new Exception("Error evaluating field "+fieldRef.getName(), e);
        }
    }

    public Object eval(EntryFieldConfig fieldMapping) throws Exception {
        try {
            if (fieldMapping.getConstant() != null) {
                return fieldMapping.getConstant();

            } else if (fieldMapping.getVariable() != null) {
                String name = fieldMapping.getVariable();
                Object value = get(name);
                if (value == null && name.startsWith("rdn.")) {
                    value = get(name.substring(4));
                }
                return value;

            } else if (fieldMapping.getExpression() != null) {
                return eval(fieldMapping.getExpression());

            } else {
                return null;
            }
        } catch (Exception e) {
            throw new Exception("Error evaluating field "+fieldMapping.getName(), e);
        }
    }

    public Object eval(MappingRule rule) throws Exception {
        try {
            if (rule.getConstant() != null) {
                return rule.getConstant();

            } else if (rule.getVariable() != null) {
                String name = rule.getVariable();
                return get(name);

            } else if (rule.getExpression() != null) {
                return eval(rule.getExpression());

            } else {
                return null;
            }
        } catch (Exception e) {
            throw new Exception("Error evaluating field "+rule.getName(), e);
        }
    }

    public Object eval(Expression expression) throws Exception {

        String foreach = expression.getForeach();
        String var = expression.getVar();
        String script = expression.getScript();

        Object value = null;
        if (foreach == null) {
            //log.debug("Evaluating expression: "+expression);
            value = eval(script);

        } else {
            //log.debug("Foreach: "+foreach);

            Object v = get(foreach);
            //log.debug("Values: "+v);

            Collection<Object> newValues = new HashSet<Object>();

            if (v != null) {

                Collection<Object> values;
                if (v instanceof Collection) {
                    values = (Collection<Object>)v;
                } else {
                    values = new ArrayList<Object>();
                    values.add(v);
                }

                for (Object o : values) {
                    set(var, o);
                    value = eval(script);
                    if (value == null) continue;

                    //log.debug(" - "+value);
                    newValues.add(value);
                }
            }

            if (newValues.size() == 1) {
                value = newValues.iterator().next();

            } else if (newValues.size() > 1) {
                value = newValues;
            }
        }

        return value;
    }

    public ClassLoader getClassLoader() {
        return classLoader;
    }

    public void setClassLoader(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }
}
