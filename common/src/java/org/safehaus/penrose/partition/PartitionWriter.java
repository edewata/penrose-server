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
package org.safehaus.penrose.partition;

import java.io.File;
import java.io.FileWriter;

import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;
import org.dom4j.tree.DefaultElement;
import org.dom4j.tree.DefaultText;
import org.safehaus.penrose.adapter.AdapterConfig;
import org.safehaus.penrose.interpreter.InterpreterConfig;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

/**
 * @author Endi S. Dewata
 */
public class PartitionWriter {

    public Logger log = LoggerFactory.getLogger(getClass());

    public PartitionWriter() {
    }

    public void write(File baseDir, PartitionConfig partitionConfig) throws Exception {
        baseDir.mkdirs();

        writePartitionXml(baseDir, partitionConfig);
    }

    public void writePartitionXml(File directory, PartitionConfig partitionConfig) throws Exception {
        File file = new File(directory, "partition.xml");

        log.debug("Writing "+file+".");

        Element element = createElement(partitionConfig);
        
        FileWriter fw = new FileWriter(file);
        OutputFormat format = OutputFormat.createPrettyPrint();
        format.setTrimText(false);

        XMLWriter writer = new XMLWriter(fw, format);
        writer.startDocument();

        writer.startDTD(
                "partition",
                "-//Penrose/DTD Partition "+getClass().getPackage().getSpecificationVersion()+"//EN",
                "http://penrose.safehaus.org/dtd/partition.dtd"
        );

        writer.write(element);
        writer.close();
    }

    public Element createElement(PartitionConfig partitionConfig)  {
        Element element = new DefaultElement("partition");

        if (!partitionConfig.isEnabled()) element.addAttribute("enabled", "false");
        if (!partitionConfig.getDepends().isEmpty()) element.addAttribute("depends", partitionConfig.getStringDepends());

        String s = partitionConfig.getDescription();
        if (s != null && !"".equals(s)) {
            Element description = new DefaultElement("description");
            description.add(new DefaultText(s));
            element.add(description);
        }

        s = partitionConfig.getPartitionClass();
        if (s != null) {
            Element partitionClass = new DefaultElement("partition-class");
            partitionClass.add(new DefaultText(s));
            element.add(partitionClass);
        }

        for (InterpreterConfig interpreterConfig : partitionConfig.getInterpreterConfigs()) {
            element.add(createElement(interpreterConfig));
        }

        for (AdapterConfig adapterConfig : partitionConfig.getAdapterConfigs()) {
            element.add(createElement(adapterConfig));
        }

        for (String sourceFile : partitionConfig.getSourceFiles()) {
            element.add(createSourceFileElement(sourceFile));
        }

        for (String mappingFile : partitionConfig.getMappingFiles()) {
            element.add(createMappingFileElement(mappingFile));
        }

        for (String moduleFile : partitionConfig.getModuleFiles()) {
            element.add(createModuleFileElement(moduleFile));
        }

        return element;
    }

    public Element createElement(InterpreterConfig interpreterConfig) {
        Element element = new DefaultElement("interpreter");
/*
        Element interpreterName = new DefaultElement("interpreter-name");
        interpreterName.add(new DefaultText(interpreterConfig.getName()));
        element.add(interpreterName);
*/
        Element interpreterClass = new DefaultElement("interpreter-class");
        interpreterClass.add(new DefaultText(interpreterConfig.getInterpreterClass()));
        element.add(interpreterClass);

        if (interpreterConfig.getDescription() != null && !"".equals(interpreterConfig.getDescription())) {
            Element description = new DefaultElement("description");
            description.add(new DefaultText(interpreterConfig.getDescription()));
            element.add(description);
        }

        for (String name : interpreterConfig.getParameterNames()) {
            String value = interpreterConfig.getParameter(name);

            Element parameter = new DefaultElement("parameter");

            Element paramName = new DefaultElement("param-name");
            paramName.add(new DefaultText(name));
            parameter.add(paramName);

            Element paramValue = new DefaultElement("param-value");
            paramValue.add(new DefaultText(value));
            parameter.add(paramValue);

            element.add(parameter);
        }

        return element;
    }

    public Element createElement(AdapterConfig adapterConfig) {
        Element element = new DefaultElement("adapter");
        element.addAttribute("name", adapterConfig.getName());

        Element adapterClass = new DefaultElement("adapter-class");
        adapterClass.add(new DefaultText(adapterConfig.getAdapterClass()));
        element.add(adapterClass);

        if (adapterConfig.getDescription() != null && !"".equals(adapterConfig.getDescription())) {
            Element description = new DefaultElement("description");
            description.add(new DefaultText(adapterConfig.getDescription()));
            element.add(description);
        }

        for (String name : adapterConfig.getParameterNames()) {
            String value = adapterConfig.getParameter(name);

            Element parameter = new DefaultElement("parameter");

            Element paramName = new DefaultElement("param-name");
            paramName.add(new DefaultText(name));
            parameter.add(paramName);

            Element paramValue = new DefaultElement("param-value");
            paramValue.add(new DefaultText(value));
            parameter.add(paramValue);

            element.add(parameter);
        }

        return element;
    }

    public Element createSourceFileElement(String sourceFile) {

        Element element = new DefaultElement("source-file");
        element.add(new DefaultText(sourceFile));

        return element;
    }

    public Element createMappingFileElement(String mappingFile) {

        Element element = new DefaultElement("mapping-file");
        element.add(new DefaultText(mappingFile));

        return element;
    }

    public Element createModuleFileElement(String moduleFile) {

        Element element = new DefaultElement("module-file");
        element.add(new DefaultText(moduleFile));

        return element;
    }
}
