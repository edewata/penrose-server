package org.safehaus.penrose.engine;

import org.safehaus.penrose.mapping.EntryMapping;
import org.safehaus.penrose.mapping.SourceMapping;
import org.safehaus.penrose.mapping.FieldMapping;
import org.safehaus.penrose.entry.SourceValues;
import org.safehaus.penrose.ldap.Attributes;
import org.safehaus.penrose.ldap.Attribute;
import org.safehaus.penrose.partition.Partition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

/**
 * @author Endi S. Dewata
 */
public class EngineTool {

    public static Logger log = LoggerFactory.getLogger(EngineTool.class);

    public static void propagateUp(
            Partition partition,
            EntryMapping entryMapping,
            SourceValues sourceValues
    ) throws Exception {

        List<EntryMapping> mappings = new ArrayList<EntryMapping>();

        while (entryMapping != null) {
            mappings.add(entryMapping);
            entryMapping = partition.getParent(entryMapping);
        }

        propagate(mappings, sourceValues);
    }

    public static void propagateDown(
            Partition partition,
            EntryMapping entryMapping,
            SourceValues sourceValues
    ) throws Exception {

        List<EntryMapping> mappings = new ArrayList<EntryMapping>();

        while (entryMapping != null) {
            mappings.add(0, entryMapping);
            entryMapping = partition.getParent(entryMapping);
        }

        propagate(mappings, sourceValues);
    }

    public static void propagate(Collection<EntryMapping> mappings, SourceValues sourceValues) throws Exception {

        boolean debug = log.isDebugEnabled();

        for (EntryMapping entryMapping : mappings) {

            Collection<SourceMapping> sourceMappings = entryMapping.getSourceMappings();
            for (SourceMapping sourceMapping : sourceMappings) {

                Collection<FieldMapping> fieldMappings = sourceMapping.getFieldMappings();
                for (FieldMapping fieldMapping : fieldMappings) {

                    String variable = fieldMapping.getVariable();
                    if (variable == null) continue;

                    int p = variable.indexOf(".");
                    if (p < 0) continue;

                    String lsourceName = sourceMapping.getName();
                    String lfieldName = fieldMapping.getName();
                    String lhs = lsourceName + "." + lfieldName;

                    String rsourceName = variable.substring(0, p);
                    String rfieldName = variable.substring(p+1);
                    String rhs = rsourceName+"."+rfieldName;

                    Attributes attributes = sourceValues.get(lsourceName);

                    if (attributes != null) {

                        Attribute attribute = attributes.get(lfieldName);

                        if (attribute != null) {
                            sourceValues.set(rsourceName, rfieldName, attribute.getValues());
                            if (debug) log.debug("Propagating " + lhs + ": " + attribute.getValues());
                        }

                    } else {
                        attributes = sourceValues.get(rsourceName);

                        if (attributes != null) {
                            Attribute attribute = attributes.get(rfieldName);

                            if (attribute != null) {
                                sourceValues.set(lsourceName, lfieldName, attribute.getValues());
                                if (debug) log.debug("Propagating " + rhs + ": " + attribute.getValues());
                            }
                        }
                    }
                }
            }
        }
    }

    public static void propagateUp(
            Partition partition,
            EntryMapping entryMapping,
            Attributes sourceValues
    ) throws Exception {

        List mappings = new ArrayList();

        while (entryMapping != null) {
            mappings.add(entryMapping);
            entryMapping = partition.getParent(entryMapping);
        }

        propagate(mappings, sourceValues);
    }

    public static void propagateDown(
            Partition partition,
            EntryMapping entryMapping,
            Attributes sourceValues
    ) throws Exception {

        List mappings = new ArrayList();

        while (entryMapping != null) {
            mappings.add(0, entryMapping);
            entryMapping = partition.getParent(entryMapping);
        }

        propagate(mappings, sourceValues);
    }

    public static void propagate(Collection mappings, Attributes sourceValues) throws Exception {

        boolean debug = log.isDebugEnabled();

        for (Iterator i=mappings.iterator(); i.hasNext(); ) {
            EntryMapping entryMapping = (EntryMapping)i.next();

            Collection sourceMappings = entryMapping.getSourceMappings();
            for (Iterator j=sourceMappings.iterator(); j.hasNext(); ) {
                SourceMapping sourceMapping = (SourceMapping)j.next();

                Collection fieldMappings = sourceMapping.getFieldMappings();
                for (Iterator k=fieldMappings.iterator(); k.hasNext(); ) {
                    FieldMapping fieldMapping = (FieldMapping)k.next();

                    String variable = fieldMapping.getVariable();
                    if (variable == null) continue;

                    int p = variable.indexOf(".");
                    if (p < 0) continue;

                    String lhs = sourceMapping.getName()+"."+fieldMapping.getName();
                    String rhs = variable;

                    Collection values = sourceValues.getValues(lhs);
                    if (values == null) {
                        values = sourceValues.getValues(rhs);
                        if (values != null) {
                            sourceValues.addValues(lhs, values);
                            if (debug) log.debug("Propagating "+lhs+": "+values);
                        }
                    } else {
                        sourceValues.addValues(rhs, values);
                        if (debug) log.debug("Propagating "+rhs+": "+values);
                    }
                }
            }
        }
    }
}
