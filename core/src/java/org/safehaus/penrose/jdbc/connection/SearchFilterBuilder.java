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
package org.safehaus.penrose.jdbc.connection;

import org.safehaus.penrose.filter.*;
import org.safehaus.penrose.mapping.*;
import org.safehaus.penrose.interpreter.Interpreter;
import org.safehaus.penrose.ldap.SourceAttributes;
import org.safehaus.penrose.directory.EntryField;
import org.safehaus.penrose.ldap.Attributes;
import org.safehaus.penrose.ldap.Attribute;
import org.safehaus.penrose.partition.Partition;
import org.safehaus.penrose.directory.*;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.util.*;

/**
 * @author Endi S. Dewata
 */
public class SearchFilterBuilder {

    public Logger log = LoggerFactory.getLogger(getClass());

    Partition partition;

    Map<String,EntrySource> primarySourceRefs = new LinkedHashMap<String,EntrySource>(); // need to maintain order
    Map<String,EntrySource> localSourceRefs = new LinkedHashMap<String,EntrySource>(); // need to maintain order
    Map<String,EntrySource> sourceRefs = new LinkedHashMap<String,EntrySource>(); // need to maintain order

    Interpreter interpreter;

    Map<String, EntrySource> sourceAliases = new LinkedHashMap<String, EntrySource>(); // need to maintain order
    Filter sourceFilter;

    public SearchFilterBuilder(
            Partition partition,
            Collection<EntrySource> localSourceRefs,
            Collection<EntrySource> sourceRefs,
            SourceAttributes sourceValues
    ) throws Exception {

        boolean debug = log.isDebugEnabled();

        this.partition = partition;

        for (EntrySource sourceRef : localSourceRefs) {
            this.localSourceRefs.put(sourceRef.getAlias(), sourceRef);
        }

        for (EntrySource sourceRef : sourceRefs) {
            this.sourceRefs.put(sourceRef.getAlias(), sourceRef);
        }

        this.interpreter = partition.newInterpreter();

        if (debug) log.debug("Creating filters:");

        for (String sourceName : sourceValues.getNames()) {
            if (!this.sourceRefs.containsKey(sourceName)) continue;

            Attributes attributes = sourceValues.get(sourceName);

            for (String fieldName : attributes.getNames()) {

                Attribute attribute = attributes.get(fieldName);

                Filter of = null;

                for (Object value : attribute.getValues()) {
                    SimpleFilter f = new SimpleFilter(sourceName + "." + fieldName, "=", value);
                    if (debug) log.debug(" - Filter " + f);

                    of = FilterTool.appendOrFilter(of, f);
                }

                sourceFilter = FilterTool.appendAndFilter(sourceFilter, of);
            }
        }
    }

    public Filter convert(
            Filter filter
    ) throws Exception {

        if (filter instanceof NotFilter) {
            return convert((NotFilter)filter);

        } else if (filter instanceof AndFilter) {
            return convert((AndFilter)filter);

        } else if (filter instanceof OrFilter) {
            return convert((OrFilter)filter);

        } else if (filter instanceof SimpleFilter) {
            return convert((SimpleFilter)filter);

        } else if (filter instanceof SubstringFilter) {
            return convert((SubstringFilter)filter);

        } else if (filter instanceof PresentFilter) {
            return convert((PresentFilter)filter);
        }

        return null;
    }

    public Filter convert(NotFilter filter) throws Exception {
        Filter newFilter = convert(filter.getFilter());
        return new NotFilter(newFilter);
    }

    public Filter convert(AndFilter filter) throws Exception {

        Filter newFilter = null;

        Collection<Filter> filters = filter.getFilters();
        for (Filter f : filters) {
            Filter nf = convert(f);
            newFilter = FilterTool.appendAndFilter(newFilter, nf);
        }

        return newFilter;
    }

    public Filter convert(OrFilter filter) throws Exception {

        Filter newFilter = null;

        Collection<Filter> filters = filter.getFilters();
        for (Filter f : filters) {
            Filter nf = convert(f);
            newFilter = FilterTool.appendOrFilter(newFilter, nf);
        }

        return newFilter;
    }

    public Filter convert(
            SimpleFilter filter
    ) throws Exception {

        boolean debug = log.isDebugEnabled();

        if (debug) log.debug("Converting filter "+filter);

        String attributeName = filter.getAttribute();
        String operator = filter.getOperator();
        Object attributeValue = filter.getValue();

        interpreter.set(attributeName, attributeValue);

        Filter newFilter = null;
        for (EntrySource sourceRef : localSourceRefs.values()) {
            String sourceName = sourceRef.getAlias();

            String alias = createTableAlias(sourceName);
            if (alias == null) continue;

            Filter f = null;
            for (EntryField fieldRef : sourceRef.getFields()) {
                String fieldName = fieldRef.getName();

                Object value = interpreter.eval(fieldRef);
                if (value == null) {
                    //if (debug) log.debug("Field "+fieldName+" is null.");
                    continue;
                }

                setTableAlias(sourceName, alias);
                SimpleFilter sf = new SimpleFilter(alias + "." + fieldName, operator, value);

                f = FilterTool.appendAndFilter(f, sf);
                if (debug) log.debug(" - Filter " + sf);
            }

            newFilter = FilterTool.appendAndFilter(newFilter, f);
        }

        interpreter.clear();

        return newFilter;
    }

    public Filter convert(
            SubstringFilter filter
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) log.debug("Converting filter "+filter);

        String attributeName = filter.getAttribute();
        Collection<Object> substrings = filter.getSubstrings();

        Filter f = null;

        for (EntrySource sourceRef : localSourceRefs.values()) {
            for (EntryField fieldRef : sourceRef.getFields()) {

                String variable = fieldRef.getVariable();
                if (variable == null || !attributeName.equals(variable)) continue;

                String sourceName = sourceRef.getAlias();
                String fieldName = fieldRef.getName();

                String alias = createTableAlias(sourceName);
                setTableAlias(sourceName, alias);

                StringBuilder sb = new StringBuilder();
                for (Object o : substrings) {
                    if (o.equals(SubstringFilter.STAR)) {
                        sb.append("%");
                    } else {
                        String substring = (String) o;
                        sb.append(substring);
                    }
                }

                String value = sb.toString();

                SimpleFilter sf = new SimpleFilter(alias+"."+fieldName, "like", value);
                if (debug) log.debug(" - Filter "+sf);
            }
        }

        return f;
    }

    public Filter convert(
            PresentFilter filter
    ) throws Exception {

        boolean debug = log.isDebugEnabled();
        if (debug) log.debug("Converting filter "+filter);

        String attributeName = filter.getAttribute();

        if (attributeName.equalsIgnoreCase("objectClass")) return null;

        Filter newFilter = null;

        for (EntrySource sourceRef : localSourceRefs.values()) {

            String sourceName = sourceRef.getAlias();
            String alias = createTableAlias(sourceName);

            for (EntryField fieldRef : sourceRef.getFields()) {
                String fieldName = fieldRef.getName();

                String variable = fieldRef.getVariable();
                if (variable == null) {
                    Expression expression = fieldRef.getExpression();
                    if (expression != null) {
                        variable = expression.getForeach();
                    }
                }

                if (variable == null) {
                    //if (debug) log.debug("Attribute "+attributeName+" can't be converted.");
                    continue;
                }

                if (!attributeName.equalsIgnoreCase(variable)) {
                    //if (debug) log.debug("Attribute "+attributeName+" doesn't match "+variable);
                    continue;
                }

                setTableAlias(sourceName, alias);

                PresentFilter f = new PresentFilter(alias + "." + fieldName);
                if (debug) log.debug(" - Filter " + f);

                newFilter = FilterTool.appendAndFilter(newFilter, f);
            }
        }

        return newFilter;
    }

    public void append(Filter filter) throws Exception {
        sourceFilter = FilterTool.appendAndFilter(sourceFilter, convert(filter));
    }

    public Filter getFilter() {
        return sourceFilter;
    }
/*
    public boolean isPrimarySource(String sourceName) {
        return primarySourceRefs.containsKey(sourceName);
    }
*/

    public String createTableAlias(String sourceName) {
        EntrySource sourceRef = sourceRefs.get(sourceName);
        if (sourceRef == null) return null;
        
        if (sourceRef.isPrimarySourceRef()) return sourceName;
        //if (isPrimarySource(sourceName)) return sourceName;

        int counter = 2;
        String alias = sourceName+counter;

        while (localSourceRefs.get(alias) != null) {
            counter++;
            alias = sourceName+counter;
        }

        return alias;
    }

    public void setTableAlias(String sourceName, String alias) {
        EntrySource sourceRef = sourceRefs.get(sourceName);
        if (sourceRef.isPrimarySourceRef()) return;
        //if (isPrimarySource(sourceName)) return;

        //SourceRef sourceRef = localSourceRefs.get(sourceName);
        sourceAliases.put(alias, sourceRef);
    }

    public Map<String, EntrySource> getSourceAliases() {
        return sourceAliases;
    }

    public void setSourceAliases(Map<String, EntrySource> sourceAliases) {
        this.sourceAliases = sourceAliases;
    }
}
