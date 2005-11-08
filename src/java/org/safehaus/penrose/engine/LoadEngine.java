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
import org.safehaus.penrose.graph.Graph;
import org.safehaus.penrose.interpreter.Interpreter;
import org.safehaus.penrose.SearchResults;
import org.safehaus.penrose.util.Formatter;
import org.safehaus.penrose.filter.Filter;
import org.safehaus.penrose.filter.FilterTool;
import org.safehaus.penrose.config.Config;
import org.apache.log4j.Logger;

import java.util.*;

import com.novell.ldap.LDAPException;

/**
 * @author Endi S. Dewata
 */
public class LoadEngine {

    Logger log = Logger.getLogger(getClass());

    private Engine engine;
    private EngineContext engineContext;

    public LoadEngine(Engine engine) {
        this.engine = engine;
        this.engineContext = engine.getEngineContext();
    }

    public void load(
            EntryDefinition entryDefinition,
            SearchResults batches,
            SearchResults loadedBatches
            ) throws Exception {

        //MRSWLock lock = getLock(entryDefinition.getDn());
        //lock.getWriteLock(Penrose.WAIT_TIMEOUT);

        try {
            while (batches.hasNext()) {
                Collection keys = (Collection)batches.next();

                log.debug(Formatter.displaySeparator(80));
                log.debug(Formatter.displayLine("LOAD", 80));
                log.debug(Formatter.displayLine("Entry: "+entryDefinition.getDn(), 80));

                AttributeValues sourceValues = new AttributeValues();
                for (Iterator i=keys.iterator(); i.hasNext(); ) {
                    Map map = (Map)i.next();
                    String dn = (String)map.get("dn");
                    AttributeValues sv = (AttributeValues)map.get("sourceValues");
                    Row filter = (Row)map.get("filter");

                    log.debug(Formatter.displayLine(" - "+dn, 80));
                    log.debug(Formatter.displayLine("   filter: "+filter, 80));

                    if (sv == null) continue;

                    sourceValues.add(sv);

                    for (Iterator j=sv.getNames().iterator(); j.hasNext(); ) {
                        String name = (String)j.next();
                        Collection values = sv.get(name);
                        log.debug(Formatter.displayLine("   - "+name+": "+values, 80));
                    }
                }

                log.debug(Formatter.displaySeparator(80));

                AttributeValues loadedSourceValues = loadEntries(sourceValues, entryDefinition, keys);

                log.debug(Formatter.displaySeparator(80));
                log.debug(Formatter.displayLine("LOAD RESULT", 80));

                int c = 1;

                for (Iterator i=loadedSourceValues.getNames().iterator(); i.hasNext(); ) {
                    String sourceName = (String)i.next();
                    Collection values = loadedSourceValues.get(sourceName);

                    for (Iterator j=values.iterator(); j.hasNext(); c++) {
                        Object object = j.next();
                        log.debug(Formatter.displayLine(" - "+sourceName+": "+object.getClass().getName(), 80));

                        if (object instanceof AttributeValues) {
                            AttributeValues avs = (AttributeValues)object;
                            for (Iterator k=avs.getNames().iterator(); k.hasNext(); ) {
                                String name = (String)k.next();
                                Collection list = avs.get(name);
                                log.debug(Formatter.displayLine("   - "+name+": "+list, 80));
                            }

                        } else {
                            log.debug(Formatter.displayLine("   - "+sourceName+": "+object, 80));
                        }
                    }
                }

                log.debug(Formatter.displaySeparator(80));

                for (Iterator i=keys.iterator(); i.hasNext(); ) {
                    Map map = (Map)i.next();

                    map.put("loadedSourceValues", loadedSourceValues);

                    loadedBatches.add(map);
                }
            }

        } finally {
            //lock.releaseWriteLock(Penrose.WAIT_TIMEOUT);
            loadedBatches.close();
        }
    }

    public AttributeValues loadEntries(
            AttributeValues sourceValues,
            EntryDefinition entryDefinition,
            Collection maps)
            throws Exception {

        Source primarySource = engine.getPrimarySource(entryDefinition);
        log.debug("Primary source: "+(primarySource == null ? null : primarySource.getName()));

        if (primarySource == null) {
            Collection sourceNames = new TreeSet();
            for (Iterator i=sourceValues.getNames().iterator(); i.hasNext(); ) {
                String name = (String)i.next();
                int index = name.indexOf(".");
                String sourceName = name.substring(0, index);
                sourceNames.add(sourceName);
            }

            AttributeValues newSourceValues = new AttributeValues();
            for (Iterator i=sourceNames.iterator(); i.hasNext(); ) {
                String sourceName = (String)i.next();
                if ("parent".equals(sourceName)) continue;

                AttributeValues sv = new AttributeValues(sourceValues);
                sv.retain(sourceName);

                newSourceValues.add(sourceName, sv);
            }

            return newSourceValues;
        }

        Collection pks = new TreeSet();
        for (Iterator i=maps.iterator(); i.hasNext(); ) {
            Map m = (Map)i.next();
            String dn = (String)m.get("dn");
            AttributeValues sv = (AttributeValues)m.get("sourceValues");
            Row pk = (Row)m.get("filter");
            pks.add(pk);
        }

        Filter filter  = FilterTool.createFilter(pks, true);

        Map map = new HashMap();
        map.put("attributeValues", sourceValues);
        map.put("filter", filter);

        Collection filters = new ArrayList();
        filters.add(map);

        LoadGraphVisitor loadVisitor = new LoadGraphVisitor(engine, entryDefinition, sourceValues, filter);
        loadVisitor.run();

        return loadVisitor.getLoadedSourceValues();
    }

    public Engine getEngine() {
        return engine;
    }

    public void setEngine(Engine engine) {
        this.engine = engine;
    }

    public EngineContext getEngineContext() {
        return engineContext;
    }

    public void setEngineContext(EngineContext engineContext) {
        this.engineContext = engineContext;
    }
}
