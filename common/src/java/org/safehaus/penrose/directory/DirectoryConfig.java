package org.safehaus.penrose.directory;

import org.safehaus.penrose.ldap.DN;
import org.safehaus.penrose.ldap.RDN;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.io.Serializable;

/**
 * @author Endi Sukma Dewata
 */
public class DirectoryConfig implements Serializable, Cloneable {

    public final static long serialVersionUID = 1L;

    public final static List<String> EMPTY_IDS  = new ArrayList<String>();
    public final static Collection<EntryConfig> EMPTY = new ArrayList<EntryConfig>();

    protected List<EntryConfig> entryConfigs                           = new ArrayList<EntryConfig>();
    protected Map<String,EntryConfig> entryConfigByName                = new LinkedHashMap<String,EntryConfig>();
    protected Map<String,Collection<EntryConfig>> entryConfigsByDn     = new LinkedHashMap<String,Collection<EntryConfig>>();
    protected Map<String,Collection<EntryConfig>> entryConfigsBySource = new LinkedHashMap<String,Collection<EntryConfig>>();

    protected List<String> rootNames                        = new ArrayList<String>();
    protected Map<String,String> parentByName               = new LinkedHashMap<String,String>();
    protected Map<String,List<String>> childrenByName       = new LinkedHashMap<String,List<String>>();

    public DirectoryConfig() {
    }

    public void addEntryConfig(EntryConfig entryConfig) throws Exception {

        Logger log = LoggerFactory.getLogger(getClass());
        boolean debug = log.isDebugEnabled();

        String entryName = entryConfig.getName();
        DN dn = entryConfig.getDn();

        if (debug) log.debug("Adding entry \""+dn+"\".");

        validate(entryConfig);

        if (entryConfigByName.containsKey(entryName)) {
            throw new Exception("Entry "+entryName+" already exists.");
        }

        entryConfigs.add(entryConfig);

        if (entryName == null) {
            int counter = 0;
            entryName = "entry"+counter;
            while (entryConfigByName.containsKey(entryName)) {
                counter++;
                entryName = "entry"+counter;
            }
            entryConfig.setName(entryName);
        }
        if (debug) log.debug(" - ID: "+ entryName);

        // index by entryName
        entryConfigByName.put(entryName, entryConfig);

        // index by dn
        String normalizedDn = dn.getNormalizedDn();
        Collection<EntryConfig> c1 = entryConfigsByDn.get(normalizedDn);
        if (c1 == null) {
            c1 = new LinkedHashSet<EntryConfig>();
            entryConfigsByDn.put(normalizedDn, c1);
        }
        c1.add(entryConfig);

        // index by source
        for (EntrySourceConfig sourceConfig : entryConfig.getSourceConfigs()) {
            String sourceName = sourceConfig.getSourceName();
            Collection<EntryConfig> c2 = entryConfigsBySource.get(sourceName);
            if (c2 == null) {
                c2 = new LinkedHashSet<EntryConfig>();
                entryConfigsBySource.put(sourceName, c2);
            }
            c2.add(entryConfig);
        }

        String parentName = entryConfig.getParentName();

        if (parentName != null) {
            if (debug) log.debug(" - Searching parent with name "+parentName);
            EntryConfig parent = getEntryConfig(parentName);

            if (parent != null) {
                if (debug) log.debug(" - Found parent \""+parent.getDn()+"\".");
                addChildName(parentName, entryConfig.getName());
                return;
            }
        }

        DN parentDn = entryConfig.getParentDn();

        if (!parentDn.isEmpty()) {

            if (debug) log.debug(" - Searching parent with dn \""+parentDn+"\".");
            Collection<EntryConfig> parents = getEntryConfigsByDn(parentDn);

            if (!parents.isEmpty()) {
                EntryConfig parent = parents.iterator().next();
                if (debug) log.debug(" - Found parent \""+parent.getDn()+"\".");
                addChildName(parent.getName(), entryConfig.getName());
                return;
            }
        }

        if (debug) log.debug(" - Add suffix \""+dn+"\"");
        rootNames.add(entryName);
    }

    public void validate(EntryConfig entryConfig) throws Exception {

        String entryName = entryConfig.getName();

        if (entryName != null) {

            char startingChar = entryName.charAt(0);
            if (!Character.isLetter(startingChar)) {
                throw new Exception("Invalid service name: "+entryName);
            }

            for (int i = 1; i<entryName.length(); i++) {
                char c = entryName.charAt(i);
                if (Character.isLetterOrDigit(c) || c == '_') continue;
                throw new Exception("Invalid service name: "+entryName);
            }

            if (entryConfigByName.containsKey(entryName)) {
                throw new Exception("Entry "+entryName+" already exists.");
            }
        }
    }

    public boolean contains(EntryConfig entryConfig) {
        return entryConfigByName.containsKey(entryConfig.getName());
    }

    public EntryConfig getEntryConfig(String entryName) {
        return entryConfigByName.get(entryName);
    }

    public String getParentName(String entryName) {
        return parentByName.get(entryName);
    }
    
    public EntryConfig getParent(EntryConfig entryConfig) {
        if (entryConfig == null) return null;

        String parentName = parentByName.get(entryConfig.getName());
        return entryConfigByName.get(parentName);
    }

    public void updateEntryConfig(String name, EntryConfig entryConfig) throws Exception {

        removeEntryConfig(name);
        addEntryConfig(entryConfig);
/*
        EntryConfig oldEntryConfig = entryConfigsById.get(name);

        DN oldParentDn = oldEntryConfig.getParentDn();
        DN parentDn = entryConfig.getParentDn();

        if (!oldParentDn.equals(parentDn)) {
            throw new Exception("Modify DN operation is not supported.");
        }

        RDN oldRdn = oldEntryConfig.getRdn();
        RDN rdn = entryConfig.getRdn();

        if (!oldRdn.equals(rdn)) {
            renameEntryConfig(oldEntryConfig, rdn);
        }

        oldEntryConfig.copy(entryConfig);
*/
    }

    public void removeEntryConfig(String name) throws Exception {
        
        Logger log = LoggerFactory.getLogger(getClass());
        boolean debug = log.isDebugEnabled();

        Collection<String> childNames = new ArrayList<String>();
        childNames.addAll(getChildNames(name));
        for (String childName : childNames) {
            removeEntryConfig(childName);
        }

        EntryConfig entryConfig = entryConfigByName.remove(name);
        if (entryConfig == null) return;

        entryConfigs.remove(entryConfig);

        String parentName = parentByName.get(name);
        if (parentName == null) {
            if (debug) log.debug("Removing root entry "+name+".");
            rootNames.remove(name);

        } else {
            if (debug) log.debug("Removing entry "+name+" from parent "+parentName+".");
            parentByName.remove(name);

            List<String> children = childrenByName.get(parentName);
            if (children != null) {
                children.remove(name);
                if (children.isEmpty()) childrenByName.remove(parentName);
            }
        }

        String normalizedDn = entryConfig.getDn().getNormalizedDn();
        Collection<EntryConfig> c = entryConfigsByDn.get(normalizedDn);
        if (c != null) {
            c.remove(entryConfig);
            if (c.isEmpty()) entryConfigsByDn.remove(normalizedDn);
        }

        for (String sourceName : entryConfig.getSourceNames()) {
            Collection<EntryConfig> c2 = entryConfigsBySource.get(sourceName);
            if (c2 != null) {
                c2.remove(entryConfig);
                if (c2.isEmpty()) entryConfigsBySource.remove(sourceName);
            }
        }
    }

    public Collection<EntryConfig> getEntryConfigs() {
        return entryConfigs;
    }

    public Collection<EntryConfig> getEntryConfigs(Collection<String> names) {
        Collection<EntryConfig> entryConfigs = new LinkedHashSet<EntryConfig>();
        for (String name : names) {
            EntryConfig entryConfig = entryConfigByName.get(name);
            if (entryConfig == null) continue;
            entryConfigs.add(entryConfig);
        }
        return entryConfigs;
    }

    public Collection<String> getEntryNames() {
        return entryConfigByName.keySet();
    }
    
    public Collection<String> getEntryNames(Collection<EntryConfig> entryConfigs) throws Exception {
        Collection<String> names = new LinkedHashSet<String>();
        for (EntryConfig entryConfig : entryConfigs) {
            names.add(entryConfig.getName());
        }
        return names;
    }

    public Collection<String> getEntryNamesByDn(DN dn) throws Exception {
        if (dn == null) return EMPTY_IDS;

        Collection<EntryConfig> list = entryConfigsByDn.get(dn.getNormalizedDn());
        if (list == null) return EMPTY_IDS;

        return getEntryNames(list);
    }

    public String getEntryNameByDn(DN dn) throws Exception {
        if (dn == null) return null;

        Collection<EntryConfig> list = entryConfigsByDn.get(dn.getNormalizedDn());
        if (list == null) return null;
        if (list.isEmpty()) return null;

        return list.iterator().next().getName();
    }

    public Collection<String> getEntryNamesBySource(String sourceName) throws Exception {
        Collection<EntryConfig> list = entryConfigsBySource.get(sourceName);
        if (list == null) return EMPTY_IDS;

        return getEntryNames(list);
    }

    public Collection<EntryConfig> getEntryConfigsBySource(String sourceName) throws Exception {
        Collection<EntryConfig> list = entryConfigsBySource.get(sourceName);
        if (list == null) return EMPTY;

        return list;
    }

    public Collection<EntryConfig> getEntryConfigsByDn(DN dn) throws Exception {
        if (dn == null) return EMPTY;

        Collection<EntryConfig> list = entryConfigsByDn.get(dn.getNormalizedDn());
        if (list == null) return EMPTY;

        return list;
    }

    public void renameChildren(EntryConfig entryConfig, String newDn) throws Exception {

        Logger log = LoggerFactory.getLogger(getClass());
        boolean debug = log.isDebugEnabled();

        if (entryConfig == null) return;
        if (newDn.equals(entryConfig.getDn().toString())) return;

        DN oldDn = entryConfig.getDn();
        if (debug) log.debug("Renaming "+oldDn+" to "+newDn);

        Collection<EntryConfig> c = getEntryConfigsByDn(oldDn);
        if (c == null) return;

        c.remove(entryConfig);
        if (c.isEmpty()) {
        	if (debug) log.debug("Last "+oldDn);
            entryConfigsByDn.remove(oldDn.getNormalizedDn());
        }

        entryConfig.setStringDn(newDn);
        Collection<EntryConfig> newList = entryConfigsByDn.get(newDn.toLowerCase());
        if (newList == null) {
        	if (debug) log.debug("First "+newDn);
            newList = new LinkedHashSet<EntryConfig>();
            entryConfigsByDn.put(newDn.toLowerCase(), newList);
        }
        newList.add(entryConfig);

        Collection<EntryConfig> children = getChildren(entryConfig);

        if (children != null) {
            //addChildren(newDn, children);

            for (EntryConfig child : children) {
                String childNewDn = child.getRdn() + "," + newDn;
                //System.out.println(" - renaming child "+child.getDn()+" to "+childNewDn);

                renameChildren(child, childNewDn);
            }

            //removeChildren(oldDn);
        }
    }

    public void renameEntryConfig(EntryConfig entryConfig, DN newDn) throws Exception {

        Logger log = LoggerFactory.getLogger(getClass());
        boolean debug = log.isDebugEnabled();

        EntryConfig oldParent = getParent(entryConfig);
        DN oldDn = entryConfig.getDn();

        if (debug) log.debug("Renaming "+oldDn+" to "+newDn);

        Collection<EntryConfig> c = entryConfigsByDn.get(oldDn.getNormalizedDn());
        if (c == null) {
        	if (debug) log.debug("Entry "+oldDn+" not found.");
            return;
        }

        c.remove(entryConfig);
        if (c.isEmpty()) {
        	if (debug) log.debug("Last "+oldDn);
            entryConfigsByDn.remove(oldDn.getNormalizedDn());
        }

        entryConfig.setDn(newDn);
        Collection<EntryConfig> newList = entryConfigsByDn.get(newDn.getNormalizedDn());
        if (newList == null) {
        	if (debug) log.debug("First "+newDn);
            newList = new LinkedHashSet<EntryConfig>();
            entryConfigsByDn.put(newDn.getNormalizedDn(), newList);
        }
        newList.add(entryConfig);

        EntryConfig newParent = getParent(entryConfig);
        if (debug) log.debug("New parent "+(newParent == null ? null : newParent.getDn()));

        if (newParent != null) {
            addChildName(newParent.getName(), entryConfig.getName());
        }

        Collection<EntryConfig> children = getChildren(entryConfig);

        if (children != null) {
            //addChildren(newDn, children);

            for (EntryConfig child : children) {
                String childNewDn = child.getRdn() + "," + newDn;
                //System.out.println(" - renaming child "+child.getDn()+" to "+childNewDn);

                renameChildren(child, childNewDn);
            }

            //removeChildren(oldDn);
        }

        if (oldParent != null) {
            Collection oldSiblings = getChildren(oldParent);
            if (oldSiblings != null) oldSiblings.remove(entryConfig);
        }

    }

    public void renameEntryConfig(EntryConfig entryConfig, RDN newRdn) throws Exception {

        Logger log = LoggerFactory.getLogger(getClass());
        boolean debug = log.isDebugEnabled();

        EntryConfig oldParent = getParent(entryConfig);
        DN oldDn = entryConfig.getDn();

        if (debug) log.debug("Renaming "+oldDn+" to "+newRdn+".");

        Collection<EntryConfig> c = entryConfigsByDn.get(oldDn.getNormalizedDn());
        if (c == null) {
        	if (debug) log.debug("Entry "+oldDn+" not found.");
            return;
        }

        c.remove(entryConfig);
        if (c.isEmpty()) {
        	if (debug) log.debug("Last "+oldDn+".");
            entryConfigsByDn.remove(oldDn.getNormalizedDn());
        }

        DN newDn = newRdn.append(oldParent.getDn());
        entryConfig.setDn(newDn);
        Collection<EntryConfig> newList = entryConfigsByDn.get(newDn.getNormalizedDn());
        if (newList == null) {
        	if (debug) log.debug("First "+newDn+".");
            newList = new LinkedHashSet<EntryConfig>();
            entryConfigsByDn.put(newDn.getNormalizedDn(), newList);
        }
        newList.add(entryConfig);
    }

    public List<String> getChildNames(String entryName) {
        if (entryName == null) return rootNames;

        List<String> children = childrenByName.get(entryName);
        if (children == null) return EMPTY_IDS;
        return children;
    }

    public void setChildNames(String entryName, List<String> childNames) throws Exception {
        removeChildNames(entryName);
        addChildNames(entryName, childNames);
    }

    public void addChildName(String entryName, String childName) throws Exception {

        Logger log = LoggerFactory.getLogger(getClass());
        boolean debug = log.isDebugEnabled();

        if (debug) log.debug("Adding child "+childName+" to entry "+entryName+".");

        if (entryName == null) {
            rootNames.add(childName);
            return;
        }

        List<String> children = childrenByName.get(entryName);
        if (children == null) {
            children = new ArrayList<String>();
            childrenByName.put(entryName, children);
        }

        children.add(childName);
        parentByName.put(childName, entryName);
    }

    public void addChildNames(String entryName, List<String> childNames) throws Exception {
        for (String childName : childNames) {
            addChildName(entryName, childName);
        }
    }

    public void removeChildName(String entryName, String childName) throws Exception {

        Logger log = LoggerFactory.getLogger(getClass());
        boolean debug = log.isDebugEnabled();

        if (debug) log.debug("Removing child "+childName+" of entry "+entryName+".");

        if (entryName == null) {
            rootNames.remove(childName);
            return;
        }

        parentByName.remove(childName);

        List<String> children = childrenByName.get(entryName);
        if (children == null) return;

        children.remove(childName);
        if (children.isEmpty()) childrenByName.remove(entryName);
    }

    public void removeChildNames(String entryName) throws Exception {

        if (entryName == null) {
            rootNames.clear();
            return;
        }

        List<String> children = childrenByName.get(entryName);
        if (children == null) return;

        List<String> list = new ArrayList<String>();
        list.addAll(children);

        for (String childName : list) {
            removeChildName(entryName, childName);
        }
    }

    public Collection<EntryConfig> getChildren(EntryConfig parentConfig) {
        return getChildren(parentConfig.getName());
    }

    public Collection<EntryConfig> getChildren(String name) {
        List<String> children = childrenByName.get(name);
        if (children == null) return EMPTY;
        return getEntryConfigs(children);
    }

    public void removeChildren(EntryConfig parentConfig) {
        List<String> names = childrenByName.remove(parentConfig.getName());
        for (String name : names) {
            parentByName.remove(name);
        }
    }

    public DN getSuffix() {
        String name = rootNames.iterator().next();
        EntryConfig rootEntry = getEntryConfig(name);
        return rootEntry.getDn();
    }
    
    public Collection<DN> getSuffixes() {
        Collection<DN> list = new LinkedHashSet<DN>();
        for (EntryConfig entryConfig : getRootEntryConfigs()) {
            DN suffix = entryConfig.getDn();
            list.add(suffix);
        }
        return list;
    }

    public String getRootName() {
        if (rootNames.isEmpty()) return null;
        return rootNames.iterator().next();
    }
    
    public List<String> getRootNames() {
        return rootNames;
    }

    public Collection<EntryConfig> getRootEntryConfigs() {
        return getEntryConfigs(getRootNames());
    }

    public boolean contains(DN dn) throws Exception {
        for (DN suffix : getSuffixes()) {

            if (suffix.isEmpty() && dn.isEmpty() // Root DSE
                    || dn.endsWith(suffix)) {
                return true;
            }
        }

        return false;
    }

    public Collection<EntryConfig> getEntryConfigs(String dn) throws Exception {
        return getEntryConfigsByDn(new DN(dn));
    }

    public Object clone() throws CloneNotSupportedException {
        DirectoryConfig directoryConfig = (DirectoryConfig)super.clone();

        directoryConfig.entryConfigs         = new ArrayList<EntryConfig>();
        directoryConfig.entryConfigByName    = new LinkedHashMap<String,EntryConfig>();
        directoryConfig.entryConfigsByDn     = new LinkedHashMap<String,Collection<EntryConfig>>();
        directoryConfig.entryConfigsBySource = new LinkedHashMap<String,Collection<EntryConfig>>();

        directoryConfig.rootNames = new ArrayList<String>();
        directoryConfig.parentByName = new LinkedHashMap<String,String>();
        directoryConfig.childrenByName = new LinkedHashMap<String,List<String>>();

        for (EntryConfig entryConfig : entryConfigs) {
            try {
                directoryConfig.addEntryConfig((EntryConfig) entryConfig.clone());
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }

        return directoryConfig;
    }
}
