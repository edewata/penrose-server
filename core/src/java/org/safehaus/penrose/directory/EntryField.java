package org.safehaus.penrose.directory;

import org.safehaus.penrose.source.Field;
import org.safehaus.penrose.mapping.Expression;

import java.util.Collection;
import java.util.ArrayList;

/**
 * @author Endi S. Dewata
 */
public class EntryField implements Cloneable {

    public final static Collection<String> EMPTY = new ArrayList<String>();

    public String sourceName;
    private Field field;

    private String name;
    private boolean primaryKey;

    private EntryFieldConfig fieldConfig;

    public EntryField(EntrySource source, Field field) throws Exception {
        this.sourceName = source.getAlias();
        this.field = field;

        name = field.getName();

        primaryKey = field.isPrimaryKey();
    }
    
    public EntryField(Entry entry, EntrySource source, Field field, EntryFieldConfig entryFieldConfig) throws Exception {
        this.sourceName = source.getAlias();
        this.field = field;
        this.fieldConfig = entryFieldConfig;

        name = entryFieldConfig.getName();

        if (entryFieldConfig.isPrimaryKey()) {
            primaryKey = entryFieldConfig.isPrimaryKey();
            return;
        }

        String variable = entryFieldConfig.getVariable();

        if (variable != null && variable.indexOf('.') < 0) {

            EntryAttributeConfig attributeMapping = entry.getAttributeConfig(variable);

            if (attributeMapping != null) {
                primaryKey = attributeMapping.isRdn();
                return;
            }
        }

        primaryKey = field.isPrimaryKey();
    }

    public String getSourceName() {
        return sourceName;
    }

    public EntryFieldConfig getFieldConfig() {
        return fieldConfig;
    }

    public void setFieldConfig(EntryFieldConfig fieldConfig) {
        this.fieldConfig = fieldConfig;
    }

    public String getName() {
        return name;
    }

    public String getOriginalName() {
        return field.getOriginalName();
    }

    public boolean isCaseSensitive() {
        return field.isCaseSensitive();
    }

    public String getType() {
        return field.getType();
    }

    public void setName(String name) {
        this.name = name;
    }

    public Field getField() {
        return field;
    }

    public void setField(Field field) {
        this.field = field;
    }

    public Collection<String> getOperations() {
        return fieldConfig == null ? EMPTY : fieldConfig.getOperations();
    }

    public boolean isPrimaryKey() {
        return primaryKey;
    }

    public void setPrimaryKey(boolean primaryKey) {
        this.primaryKey = primaryKey;
    }

    public Object getConstant() {
        return fieldConfig == null ? field.getConstant() : fieldConfig.getConstant();
    }

    public String getVariable() {
        return fieldConfig == null ? field.getVariable() : fieldConfig.getVariable();
    }

    public Expression getExpression() {
        return fieldConfig == null ? field.getExpression() : fieldConfig.getExpression();
    }

    public String getEncryption() {
        return fieldConfig.getEncryption();
    }
    
    public String toString() {
        return sourceName+"."+name;
    }

    public Object clone() throws CloneNotSupportedException {

        EntryField fieldRef = (EntryField)super.clone();

        fieldRef.sourceName = sourceName;
        fieldRef.field = field;

        fieldRef.name = name;
        fieldRef.primaryKey = primaryKey;

        fieldRef.fieldConfig = fieldConfig;

        return fieldRef;
    }
}
