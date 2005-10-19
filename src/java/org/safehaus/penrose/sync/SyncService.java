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
package org.safehaus.penrose.sync;

import org.safehaus.penrose.SearchResults;
import org.safehaus.penrose.config.Config;
import org.safehaus.penrose.thread.MRSWLock;
import org.safehaus.penrose.thread.Queue;
import org.safehaus.penrose.connection.Connection;
import org.safehaus.penrose.filter.Filter;
import org.safehaus.penrose.mapping.*;
import org.apache.log4j.Logger;
import org.ietf.ldap.LDAPException;

import java.util.*;

/**
 * @author Endi S. Dewata
 */
public class SyncService {

    public final static int WAIT_TIMEOUT = 10000; // wait timeout is 10 seconds

    Logger log = Logger.getLogger(getClass());

    public SyncContext syncContext;

    private Map locks = new HashMap();
    private Queue queue = new Queue();

    public SyncService(SyncContext syncContext) throws Exception {
        this.syncContext = syncContext;
    }

    public synchronized MRSWLock getLock(Source source) {
		String name = source.getConnectionName() + "." + source.getSourceName();

		MRSWLock lock = (MRSWLock)locks.get(name);

		if (lock == null) lock = new MRSWLock(queue);
		locks.put(name, lock);

		return lock;
	}

    public int bind(Source source, EntryDefinition entry, AttributeValues attributeValues, String password) throws Exception {
        log.debug("----------------------------------------------------------------");
        log.debug("Binding as entry in "+source.getName());
        log.debug("Values: "+attributeValues);

        MRSWLock lock = getLock(source);
        lock.getReadLock(WAIT_TIMEOUT);

        try {

	        Map entries = syncContext.getTransformEngine().split(source, attributeValues);

	        for (Iterator i=entries.keySet().iterator(); i.hasNext(); ) {
	            Row pk = (Row)i.next();
	            AttributeValues sourceValues = (AttributeValues)entries.get(pk);

                log.debug("Bind to "+source.getName()+" as "+pk+": "+sourceValues);

                Connection connection = syncContext.getConnection(source.getConnectionName());
	            int rc = connection.bind(source, sourceValues, password);

	            if (rc != LDAPException.SUCCESS) return rc;
	        }

        } finally {
        	lock.releaseReadLock(WAIT_TIMEOUT);
        }

        return LDAPException.SUCCESS;
    }

    public int add(Source source, AttributeValues sourceValues) throws Exception {

        log.debug("----------------------------------------------------------------");
        log.debug("Adding entry into "+source.getName());
        log.debug("Values: "+sourceValues);

        MRSWLock lock = getLock(source);
        lock.getWriteLock(WAIT_TIMEOUT);

        Config config = syncContext.getConfig(source);
        ConnectionConfig connectionConfig = config.getConnectionConfig(source.getConnectionName());
        SourceDefinition sourceDefinition = connectionConfig.getSourceDefinition(source.getSourceName());

        try {
            Collection pks = syncContext.getTransformEngine().getPrimaryKeys(source, sourceValues);

            // Add rows
            for (Iterator i = pks.iterator(); i.hasNext();) {
                Row pk = (Row) i.next();
                AttributeValues newEntry = (AttributeValues)sourceValues.clone();
                newEntry.set(pk);
                log.debug("ADDING ROW: " + newEntry);

                // Add row to source table in the source database/directory
                Connection connection = syncContext.getConnection(source.getConnectionName());
                int rc = connection.add(source, newEntry);
                if (rc != LDAPException.SUCCESS) return rc;
            }

            syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).invalidate();

        } finally {
        	lock.releaseWriteLock(WAIT_TIMEOUT);
        }

        return LDAPException.SUCCESS;
    }

    public int delete(Source source, AttributeValues sourceValues) throws Exception {

        log.info("-------------------------------------------------");
        log.debug("Deleting entry in "+source.getName());

        MRSWLock lock = getLock(source);
        lock.getWriteLock(WAIT_TIMEOUT);

        Config config = syncContext.getConfig(source);
        ConnectionConfig connectionConfig = config.getConnectionConfig(source.getConnectionName());
        SourceDefinition sourceDefinition = connectionConfig.getSourceDefinition(source.getSourceName());

        try {
            Collection pks = syncContext.getTransformEngine().getPrimaryKeys(source, sourceValues);

            // Remove rows
            for (Iterator i = pks.iterator(); i.hasNext();) {
                Row pk = (Row) i.next();
                AttributeValues oldEntry = (AttributeValues)sourceValues.clone();
                oldEntry.set(pk);
                log.debug("DELETE ROW: " + oldEntry);

                // Delete row from source table in the source database/directory
                Connection connection = syncContext.getConnection(source.getConnectionName());
                int rc = connection.delete(source, oldEntry);
                if (rc != LDAPException.SUCCESS)
                    return rc;

                // Delete row from source table in the cache
                syncContext.getSourceDataCache(connectionConfig, sourceDefinition).remove(pk);
            }

            syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).invalidate();

        } finally {
            lock.releaseWriteLock(WAIT_TIMEOUT);
        }

        return LDAPException.SUCCESS;
    }

    public int modify(Source source, AttributeValues oldValues, AttributeValues newValues) throws Exception {

        log.debug("----------------------------------------------------------------");
        log.debug("Modifying entry in " + source.getName());
        log.debug("Old values: " + oldValues);
        log.debug("New values: " + newValues);

        MRSWLock lock = getLock(source);
        lock.getWriteLock(WAIT_TIMEOUT);

        Config config = syncContext.getConfig(source);
        ConnectionConfig connectionConfig = config.getConnectionConfig(source.getConnectionName());
        SourceDefinition sourceDefinition = connectionConfig.getSourceDefinition(source.getSourceName());

        try {
            Collection oldPKs = syncContext.getTransformEngine().getPrimaryKeys(source, oldValues);
            Collection newPKs = syncContext.getTransformEngine().getPrimaryKeys(source, newValues);

            log.debug("Old PKs: " + oldPKs);
            log.debug("New PKs: " + newPKs);

            Set addRows = new HashSet(newPKs);
            addRows.removeAll(oldPKs);
            log.debug("PKs to add: " + addRows);

            Set removeRows = new HashSet(oldPKs);
            removeRows.removeAll(newPKs);
            log.debug("PKs to remove: " + removeRows);

            Set replaceRows = new HashSet(oldPKs);
            replaceRows.retainAll(newPKs);
            log.debug("PKs to replace: " + replaceRows);

            // Add rows
            for (Iterator i = addRows.iterator(); i.hasNext();) {
                Row pk = (Row) i.next();
                AttributeValues newEntry = (AttributeValues)newValues.clone();
                newEntry.set(pk);
                log.debug("ADDING ROW: " + newEntry);

                // Add row to source table in the source database/directory
                Connection connection = syncContext.getConnection(source.getConnectionName());
                int rc = connection.add(source, newEntry);
                if (rc != LDAPException.SUCCESS) return rc;
            }

            // Remove rows
            for (Iterator i = removeRows.iterator(); i.hasNext();) {
                Row pk = (Row) i.next();
                AttributeValues oldEntry = (AttributeValues)oldValues.clone();
                oldEntry.set(pk);
                log.debug("DELETE ROW: " + oldEntry);

                // Delete row from source table in the source database/directory
                Connection connection = syncContext.getConnection(source.getConnectionName());
                int rc = connection.delete(source, oldEntry);
                if (rc != LDAPException.SUCCESS)
                    return rc;

                // Delete row from source table in the cache
                syncContext.getSourceDataCache(connectionConfig, sourceDefinition).remove(pk);
            }

            // Replace rows
            for (Iterator i = replaceRows.iterator(); i.hasNext();) {
                Row pk = (Row) i.next();
                AttributeValues oldEntry = (AttributeValues)oldValues.clone();
                oldEntry.set(pk);
                AttributeValues newEntry = (AttributeValues)newValues.clone();
                newEntry.set(pk);
                log.debug("REPLACE ROW: " + oldEntry+" with "+newEntry);

                // Modify row from source table in the source database/directory
                Connection connection = syncContext.getConnection(source.getConnectionName());
                int rc = connection.modify(source, oldEntry, newEntry);
                if (rc != LDAPException.SUCCESS) return rc;

                // Modify row from source table in the cache
                syncContext.getSourceDataCache(connectionConfig, sourceDefinition).remove(pk);
            }

            syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).invalidate();

        } finally {
            lock.releaseWriteLock(WAIT_TIMEOUT);
        }

        return LDAPException.SUCCESS;
    }

    public Collection search(
            Source source,
            Filter filter)
            throws Exception {

        // log.debug("Searching source "+source.getName()+" with filter "+filter);

        Collection results = new ArrayList();
        if (source.getSourceName() == null) return results;

        Config config = syncContext.getConfig(source);
        ConnectionConfig connectionConfig = config.getConnectionConfig(source.getConnectionName());
        SourceDefinition sourceDefinition = connectionConfig.getSourceDefinition(source.getSourceName());

        Collection uniqueFieldDefinitions = config.getUniqueFieldDefinitions(source);

        log.debug("Checking source filter cache for "+filter);
        Collection pks = syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).get(filter);

        if (pks != null) {
            log.debug("Source filter cache found: "+pks);
            //log.debug("Loading source "+source.getName()+" with pks "+pks);
            results.addAll(load(source, pks));
            return results;
        }

        log.debug("Source filter cache not found.");

        String method = sourceDefinition.getParameter(SourceDefinition.LOADING_METHOD);
        //log.debug("Loading method: "+method);

        if (SourceDefinition.SEARCH_AND_LOAD.equals(method)) {
            log.debug("Searching source "+source.getName()+" with filter "+filter);
            SearchResults sr = searchEntries(source, filter);
            pks = new ArrayList();
            pks.addAll(sr.getAll());

            log.debug("Loading source "+source.getName()+" with pks "+pks);
            results.addAll(load(source, pks));

        } else {
            log.debug("Loading source "+source.getName()+" with filter "+filter);
            Map map = loadEntries(source, filter);
            pks = new TreeSet();
            pks.addAll(map.keySet());
            results.addAll(map.values());

            Collection uniqueKeys = new TreeSet();

            for (Iterator i=map.keySet().iterator(); i.hasNext(); ) {
                Row pk = (Row)i.next();
                Row npk = syncContext.getSchema().normalize(pk);
                AttributeValues values = (AttributeValues)map.get(pk);
                syncContext.getSourceDataCache(connectionConfig, sourceDefinition).put(npk, values);

                Filter f = syncContext.getFilterTool().createFilter(npk);
                Collection list = new TreeSet();
                list.add(npk);

                log.debug("Storing source filter cache "+f+": "+list);
                syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(f, list);

                //log.debug("Unique fields:");
                for (Iterator j=uniqueFieldDefinitions.iterator(); j.hasNext(); ) {
                    FieldDefinition fieldDefinition = (FieldDefinition)j.next();
                    Object value = values.getOne(fieldDefinition.getName());

                    Row uniqueKey = new Row();
                    uniqueKey.set(fieldDefinition.getName(), value);

                    //f = syncContext.getFilterTool().createFilter(uniqueKey);
                    //list = new TreeSet();
                    //list.add(npk);

                    //log.debug(" - "+f+" => "+list);
                    //syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(f, list);

                    uniqueKeys.add(uniqueKey);
                }
/*
                log.debug("Indexed fields:");
                for (Iterator j=indexedFieldDefinitions.iterator(); j.hasNext(); ) {
                    FieldDefinition fieldDefinition = (FieldDefinition)j.next();
                    Collection v = values.get(fieldDefinition.getName());

                    for (Iterator k=v.iterator(); k.hasNext(); ) {
                        Object value = k.next();

                        Row indexKey = new Row();
                        indexKey.set(fieldDefinition.getName(), value);

                        f = syncContext.getFilterTool().createFilter(indexKey);

                        list = syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).get(f);
                        if (list == null) list = new TreeSet();
                        list.add(npk);

                        log.debug("Storing source filter cache "+f+": "+list);
                        syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(f, list);
                    }
                }
*/
            }

            if (!uniqueKeys.isEmpty()) {
                Filter f = syncContext.getFilterTool().createFilter(uniqueKeys);
                log.debug("Storing source filter cache "+f+": "+pks);
                syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(f, pks);
            }
        }

        log.debug("Storing source filter cache "+filter+": "+pks);
        syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(filter, pks);

        Filter newFilter = syncContext.getFilterTool().createFilter(pks);
        if (newFilter != null) {
            log.debug("Storing source filter cache "+newFilter+": "+pks);
            syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(newFilter, pks);
        }

/*
        log.debug("Checking source cache for pks "+pks);
        Map loadedRows = syncContext.getSourceDataCache(connectionConfig, sourceDefinition).search(pks);
        log.debug("Loaded rows: "+loadedRows.keySet());
        results.putAll(loadedRows);

        Collection pksToLoad = new HashSet();
        pksToLoad.addAll(pks);
        pksToLoad.removeAll(results.keySet());
        pksToLoad.removeAll(loadedRows.keySet());

        log.debug("PKs to load: "+pksToLoad);
        if (!pksToLoad.isEmpty()) {
            Filter newFilter = syncContext.getFilterTool().createFilter(pksToLoad);
            Map map = loadEntries(source, newFilter);
            results.putAll(map);

            for (Iterator i=map.keySet().iterator(); i.hasNext(); ) {
                Row pk = (Row)i.next();
                AttributeValues values = (AttributeValues)map.get(pk);
                syncContext.getSourceDataCache(connectionConfig, sourceDefinition).put(pk, values);
            }

            syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(newFilter, map.keySet());
        }
*/
        return results;
    }

    public Collection load(
            Source source,
            Collection keys)
            throws Exception {

        //log.debug("Loading source "+source.getName()+" with keys "+keys);

        Map results = new TreeMap();
        if (source.getSourceName() == null) return results.values();

        Config config = syncContext.getConfig(source);
        ConnectionConfig connectionConfig = config.getConnectionConfig(source.getConnectionName());
        SourceDefinition sourceDefinition = connectionConfig.getSourceDefinition(source.getSourceName());

        Collection uniqueFieldDefinitions = config.getUniqueFieldDefinitions(source);
        Collection missingKeys = new ArrayList();

        //log.debug("Searching source data cache for "+keys);
        Map loadedRows = syncContext.getSourceDataCache(connectionConfig, sourceDefinition).search(keys, missingKeys);

        //log.debug("Loaded rows: "+loadedRows.keySet());
        results.putAll(loadedRows);

        Collection keysToLoad = new TreeSet();
        keysToLoad.addAll(missingKeys);
        //keysToLoad.removeAll(results.keySet());
        //keysToLoad.removeAll(loadedRows.keySet());

        //log.debug("PKs to load: "+keysToLoad);
        if (!keysToLoad.isEmpty()) {
            Filter newFilter = syncContext.getFilterTool().createFilter(keysToLoad);
            Map map = loadEntries(source, newFilter);
            results.putAll(map);

            Collection uniqueKeys = new TreeSet();

            for (Iterator i=map.keySet().iterator(); i.hasNext(); ) {
                Row pk = (Row)i.next();
                Row npk = syncContext.getSchema().normalize(pk);
                AttributeValues values = (AttributeValues)map.get(pk);

                syncContext.getSourceDataCache(connectionConfig, sourceDefinition).put(npk, values);

                Filter f = syncContext.getFilterTool().createFilter(npk);
                Collection list = new TreeSet();
                list.add(npk);

                log.debug("Storing source filter cache "+f+": "+list);
                syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(f, list);

                //log.debug("Unique fields:");
                for (Iterator j=uniqueFieldDefinitions.iterator(); j.hasNext(); ) {
                    FieldDefinition fieldDefinition = (FieldDefinition)j.next();
                    Object value = values.getOne(fieldDefinition.getName());

                    Row uniqueKey = new Row();
                    uniqueKey.set(fieldDefinition.getName(), value);

                    //f = syncContext.getFilterTool().createFilter(normalizedUniqueKey);
                    //list = new TreeSet();
                    //list.add(npk);

                    //log.debug(" - "+f+" => "+list);
                    //syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(f, list);

                    uniqueKeys.add(uniqueKey);
                }
/*
                log.debug("Indexed fields:");
                for (Iterator j=indexedFieldDefinitions.iterator(); j.hasNext(); ) {
                    FieldDefinition fieldDefinition = (FieldDefinition)j.next();
                    Collection v = values.get(fieldDefinition.getName());

                    for (Iterator k=v.iterator(); k.hasNext(); ) {
                        Object value = k.next();

                        Row indexKey = new Row();
                        indexKey.set(fieldDefinition.getName(), value);
                        Row normalizedIndexKey = syncContext.getSchema().normalize(indexKey);

                        f = syncContext.getFilterTool().createFilter(normalizedIndexKey);

                        list = syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).get(f);
                        if (list == null) list = new TreeSet();
                        list.add(npk);

                        log.debug("Storing source filter cache "+f+": "+list);
                        syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(f, list);
                    }
                }
*/
            }

            if (!uniqueKeys.isEmpty()) {
                Filter f = syncContext.getFilterTool().createFilter(uniqueKeys);
                log.debug("Storing source filter cache "+f+": "+keys);
                syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(f, keys);
            }

            Collection list = new TreeSet();
            list.addAll(map.keySet());
            log.debug("Storing source filter cache "+newFilter+": "+list);
            syncContext.getSourceFilterCache(connectionConfig, sourceDefinition).put(newFilter, list);
        }

        return results.values();
    }

    public SearchResults searchEntries(Source source, Filter filter) throws Exception {

        SearchResults results = new SearchResults();

        Config config = syncContext.getConfig(source);
        ConnectionConfig connectionConfig = config.getConnectionConfig(source.getConnectionName());
        SourceDefinition sourceDefinition = connectionConfig.getSourceDefinition(source.getSourceName());

        String s = sourceDefinition.getParameter(SourceDefinition.SIZE_LIMIT);
        int sizeLimit = s == null ? SourceDefinition.DEFAULT_SIZE_LIMIT : Integer.parseInt(s);

        Connection connection = syncContext.getConnection(source.getConnectionName());
        SearchResults sr;
        try {
            sr = connection.search(source, filter, sizeLimit);

        } catch (Exception e) {
            e.printStackTrace();
            results.close();
            return results;
        }

        //log.debug("Search results:");

        for (Iterator i=sr.iterator(); i.hasNext();) {
            Row pk = (Row)i.next();

            Row npk = syncContext.getSchema().normalize(pk);
            //log.debug(" - PK: "+npk);

            results.add(npk);
        }

        results.setReturnCode(sr.getReturnCode());
        results.close();

        return results;
    }

    public Map loadEntries(Source source, Filter filter) throws Exception {

        Map results = new TreeMap();

        Config config = syncContext.getConfig(source);
        ConnectionConfig connectionConfig = config.getConnectionConfig(source.getConnectionName());
        SourceDefinition sourceDefinition = connectionConfig.getSourceDefinition(source.getSourceName());

        String s = sourceDefinition.getParameter(SourceDefinition.SIZE_LIMIT);
        int sizeLimit = s == null ? SourceDefinition.DEFAULT_SIZE_LIMIT : Integer.parseInt(s);

        Connection connection = syncContext.getConnection(source.getConnectionName());
        SearchResults sr;
        try {
            sr = connection.load(source, filter, sizeLimit);
        } catch (Exception e) {
            e.printStackTrace();
            return results;
        }

        //log.debug("Load results:");

        for (Iterator i=sr.iterator(); i.hasNext();) {
            AttributeValues av = (AttributeValues)i.next();

            Row pk = new Row();

            Collection fields = sourceDefinition.getFieldDefinitions();
            for (Iterator j=fields.iterator(); j.hasNext(); ) {
                FieldDefinition fieldDefinition = (FieldDefinition)j.next();
                if (!fieldDefinition.isPrimaryKey()) continue;

                String name = fieldDefinition.getName();
                Collection values = av.get(name);
                if (values == null) {
                    pk = null;
                    break;
                }

                Object value = values.iterator().next();
                pk.set(name, value);
            }

            if (pk == null) continue;
            
            Row npk = syncContext.getSchema().normalize(pk);
            //log.debug(" - PK: "+npk);

            results.put(npk, av);
        }

        return results;
    }

}
