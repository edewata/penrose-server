/**
 * Copyright (c) 2000-2005, Identyx Corporation.
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
package org.safehaus.penrose.engine;

import org.safehaus.penrose.mapping.*;
import org.safehaus.penrose.graph.GraphVisitor;
import org.safehaus.penrose.graph.GraphIterator;
import org.safehaus.penrose.util.Formatter;
import org.safehaus.penrose.partition.Partition;
import org.safehaus.penrose.partition.SourceConfig;
import org.ietf.ldap.LDAPException;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.util.*;

/**
 * @author Endi S. Dewata
 */
public class DeleteGraphVisitor extends GraphVisitor {

    Logger log = LoggerFactory.getLogger(getClass());

    public Engine engine;
    public EntryMapping entryMapping;
    public AttributeValues sourceValues;

    private int returnCode = LDAPException.SUCCESS;

    public DeleteGraphVisitor(
            Engine engine,
            EntryMapping entryMapping,
            AttributeValues sourceValues
            ) throws Exception {

        this.engine = engine;
        this.entryMapping = entryMapping;
        this.sourceValues = sourceValues;
    }

    public void visitNode(GraphIterator graphIterator, Object node) throws Exception {

        SourceMapping sourceMapping = (SourceMapping)node;

        if (log.isDebugEnabled()) {
            log.debug(Formatter.displaySeparator(40));
            log.debug(Formatter.displayLine("Visiting "+sourceMapping.getName(), 40));
            log.debug(Formatter.displaySeparator(40));
        }

        if (sourceMapping.isReadOnly() || !sourceMapping.isIncludeOnDelete()) {
            log.debug("Source "+sourceMapping.getName()+" is not included on delete");
            graphIterator.traverseEdges(node);
            return;
        }

        if (entryMapping.getSourceMapping(sourceMapping.getName()) == null) {
            log.debug("Source "+sourceMapping.getName()+" is not defined in entry "+entryMapping.getDn());
            graphIterator.traverseEdges(node);
            return;
        }

        log.debug("Deleting values:");
        AttributeValues newSourceValues = new AttributeValues();
        for (Iterator i=sourceValues.getNames().iterator(); i.hasNext(); ) {
            String name = (String)i.next();
            if (!name.startsWith(sourceMapping.getName()+".")) continue;

            Collection values = sourceValues.get(name);
            log.debug(" - "+name+": "+values);

            name = name.substring(sourceMapping.getName().length()+1);
            newSourceValues.set(name, values);
        }

        Partition partition = engine.getPartitionManager().getPartition(entryMapping);
        SourceConfig sourceConfig = partition.getSourceConfig(sourceMapping.getSourceName());

        returnCode = engine.getConnector().delete(partition, sourceConfig, newSourceValues);
        if (returnCode != LDAPException.SUCCESS) return;

        graphIterator.traverseEdges(node);
    }

    public int getReturnCode() {
        return returnCode;
    }

    public void setReturnCode(int returnCode) {
        this.returnCode = returnCode;
    }
}
