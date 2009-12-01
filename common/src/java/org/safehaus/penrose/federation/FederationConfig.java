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
package org.safehaus.penrose.federation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.*;

/**
 * @author Endi S. Dewata
 */
public class FederationConfig implements Serializable, Cloneable {

    public final static long serialVersionUID = 1L;

    protected Map<String,FederationRepositoryConfig> repositories = new LinkedHashMap<String,FederationRepositoryConfig>();

    protected Map<String,FederationPartitionConfig> partitions = new LinkedHashMap<String,FederationPartitionConfig>();
    protected Map<String,Collection<String>> partitionsByRepository = new LinkedHashMap<String,Collection<String>>();

    public FederationConfig() {
    }

    public void clear() {
        repositories.clear();
        partitions.clear();
        partitionsByRepository.clear();
    }
    
    boolean equals(Object o1, Object o2) {
        if (o1 == null && o2 == null) return true;
        if (o1 != null) return o1.equals(o2);
        return o2.equals(o1);
    }

    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null) return false;
        if (object.getClass() != this.getClass()) return false;

        FederationConfig federationConfig = (FederationConfig)object;

        if (!equals(repositories, federationConfig.repositories)) return false;
        if (!equals(partitions, federationConfig.partitions)) return false;
        if (!equals(partitionsByRepository, federationConfig.partitionsByRepository)) return false;

        return true;
    }

    public void copy(FederationConfig federationConfig) throws CloneNotSupportedException {

        repositories = new LinkedHashMap<String,FederationRepositoryConfig>();

        for (FederationRepositoryConfig repository : federationConfig.repositories.values()) {
            addRepository((FederationRepositoryConfig) repository.clone());
        }

        partitions = new LinkedHashMap<String,FederationPartitionConfig>();
        partitionsByRepository = new LinkedHashMap<String,Collection<String>>();

        for (FederationPartitionConfig partitionConfig : federationConfig.partitions.values()) {
            addPartition((FederationPartitionConfig) partitionConfig.clone());
        }
    }

    public Object clone() throws CloneNotSupportedException {

        FederationConfig federationConfig = (FederationConfig)super.clone();
        federationConfig.copy(this);

        return federationConfig;
    }

    public Collection<FederationRepositoryConfig> getRepositories() {
        Collection<FederationRepositoryConfig> list = new ArrayList<FederationRepositoryConfig>();
        list.addAll(repositories.values());
        return list;
    }

    public FederationRepositoryConfig getRepository(String name) {
        return repositories.get(name);
    }

    public Collection<FederationRepositoryConfig> getRepositories(String type) {

        Collection<FederationRepositoryConfig> list = new TreeSet<FederationRepositoryConfig>();

        for (FederationRepositoryConfig repository : repositories.values()) {
            if (type.equals(repository.getType())) {
                list.add(repository);
            }
        }

        return list;
    }

    public void addRepository(FederationRepositoryConfig repository) {

        Logger log = LoggerFactory.getLogger(getClass());

        String name = repository.getName();
        String type = repository.getType();

        log.debug("Adding "+name+" repository ("+type+").");

        repositories.put(name, repository);
    }

    public void updateRepository(FederationRepositoryConfig repository) {

        Logger log = LoggerFactory.getLogger(getClass());

        String name = repository.getName();

        log.debug("Updating "+name+" repository.");

        repositories.put(name, repository);
    }

    public FederationRepositoryConfig removeRepository(String name) {

        Logger log = LoggerFactory.getLogger(getClass());
        log.debug("Removing "+name+" repository.");

        return repositories.remove(name);
    }

    public Collection<String> getRepositoryNames(String type) {
        Collection<String> list = new ArrayList<String>();

        for (FederationRepositoryConfig repository : repositories.values()) {
            if (type.equals(repository.getType())) {
                list.add(repository.getName());
            }
        }

        return list;
    }

    public Collection<String> getRepositoryNames() {
        Collection<String> list = new ArrayList<String>();
        list.addAll(repositories.keySet());
        return list;
    }

    public Collection<FederationPartitionConfig> getPartitions() {
        Collection<FederationPartitionConfig> list = new ArrayList<FederationPartitionConfig>();
        list.addAll(partitions.values());
        return list;
    }

    public FederationPartitionConfig getPartition(String name) {
        return partitions.get(name);
    }

    public FederationPartitionConfig removePartition(String name) {
        FederationPartitionConfig partitionConfig = partitions.remove(name);
        String partitionName = partitionConfig.getName();

        for (String repositoryRef : partitionConfig.getRepositoryRefNames()) {
            String repositoryName = partitionConfig.getRepository(repositoryRef);

            Collection<String> list = partitionsByRepository.get(repositoryName);
            if (list == null) continue;

            list.remove(partitionName);
            if (list.isEmpty()) partitionsByRepository.remove(repositoryName);
        }

        return partitionConfig;
    }

    public void addPartition(FederationPartitionConfig partitionConfig) {

        Logger log = LoggerFactory.getLogger(getClass());

        String partitionName = partitionConfig.getName();

        log.debug("Adding "+partitionName+" partition.");
        partitions.put(partitionName, partitionConfig);

        for (String repositoryRef : partitionConfig.getRepositoryRefNames()) {
            String repositoryName = partitionConfig.getRepository(repositoryRef);

            Collection<String> list = partitionsByRepository.get(repositoryName);
            if (list == null) {
                list = new ArrayList<String>();
                partitionsByRepository.put(repositoryName, list);
            }
            list.add(partitionName);
        }

    }

    public Collection<String> getPartitionNames() {
        Collection<String> list = new ArrayList<String>();
        list.addAll(partitions.keySet());
        return list;
    }

    public Collection<String> getPartitionNames(String repositoryName) {
        Collection<String> results = new ArrayList<String>();

        Collection<String> list = partitionsByRepository.get(repositoryName);
        if (list != null) {
            results.addAll(list);
        }

        return results;
    }
}