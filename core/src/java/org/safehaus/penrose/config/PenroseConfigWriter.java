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
package org.safehaus.penrose.config;

import java.io.FileWriter;
import java.io.Writer;
import java.io.File;

import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;
import org.dom4j.tree.DefaultElement;
import org.dom4j.tree.DefaultText;
import org.safehaus.penrose.adapter.AdapterConfig;
import org.safehaus.penrose.interpreter.InterpreterConfig;
import org.safehaus.penrose.user.UserConfig;
import org.safehaus.penrose.session.SessionConfig;
import org.safehaus.penrose.Penrose;
import org.safehaus.penrose.PenroseConfig;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

/**
 * @author Endi S. Dewata
 */
public class PenroseConfigWriter {

    public Logger log = LoggerFactory.getLogger(getClass());

    public PenroseConfigWriter() throws Exception {
    }

    public void write(File file, PenroseConfig penroseConfig) throws Exception {

        Element element = createElement(penroseConfig);

        file.getParentFile().mkdirs();
        Writer writer = new FileWriter(file);

        OutputFormat format = OutputFormat.createPrettyPrint();
        format.setTrimText(false);

        XMLWriter xmlWriter = new XMLWriter(writer, format);
        xmlWriter.startDocument();

        xmlWriter.startDTD(
                "server",
                "-//Penrose/DTD Server "+Penrose.SPECIFICATION_VERSION+"//EN",
                "http://penrose.safehaus.org/dtd/server.dtd"
        );

        xmlWriter.write(element);
        xmlWriter.close();

        writer.close();
    }

    public Element createElement(PenroseConfig penroseConfig) {
        Element element = new DefaultElement("server");

        for (String name : penroseConfig.getSystemPropertyNames()) {
            String value = penroseConfig.getSystemProperty(name);

            Element parameter = new DefaultElement("system-property");

            Element paramName = new DefaultElement("property-name");
            paramName.add(new DefaultText(name));
            parameter.add(paramName);

            Element paramValue = new DefaultElement("property-value");
            paramValue.add(new DefaultText(value));
            parameter.add(paramValue);

            element.add(parameter);
        }
/*
        for (SchemaConfig schemaConfig : penroseConfig.getSchemaConfigs()) {

            Element schema = new DefaultElement("schema");
            if (schemaConfig.getName() != null) schema.addAttribute("name", schemaConfig.getName());
            if (schemaConfig.getPath() != null) schema.addAttribute("path", schemaConfig.getPath());

            element.add(schema);
        }
*/
        for (InterpreterConfig interpreterConfig : penroseConfig.getInterpreterConfigs()) {
            element.add(createElement(interpreterConfig));
        }

        if (penroseConfig.getSessionConfig() != null) {
            SessionConfig sessionConfig = penroseConfig.getSessionConfig();
            element.add(toElement(sessionConfig));
        }

        for (AdapterConfig adapterConfig : penroseConfig.getAdapterConfigs()) {
            element.add(createElement(adapterConfig));
        }

        UserConfig rootUserConfig = penroseConfig.getRootUserConfig();
        if (rootUserConfig != null ) {
            Element rootElement = new DefaultElement("root");

            if (rootUserConfig.getDn() != null) {
                Element rootDn = new DefaultElement("root-dn");
                rootDn.add(new DefaultText(rootUserConfig.getDn().toString()));
                rootElement.add(rootDn);
            }

            if (rootUserConfig.getPassword() != null) {
                Element rootPassword = new DefaultElement("root-password");
                rootPassword.add(new DefaultText(new String(rootUserConfig.getPassword())));
                rootElement.add(rootPassword);
            }

            element.add(rootElement);
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

    public Element toElement(SessionConfig sessionConfig) {
        Element element = new DefaultElement("session");

        if (sessionConfig.getDescription() != null && !"".equals(sessionConfig.getDescription())) {
            Element description = new DefaultElement("description");
            description.add(new DefaultText(sessionConfig.getDescription()));
            element.add(description);
        }

        for (String name : sessionConfig.getParameterNames()) {
            String value = sessionConfig.getParameter(name);

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
}
