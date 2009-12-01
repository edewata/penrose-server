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
package org.safehaus.penrose.schema;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.io.FileReader;
import java.io.File;

/**
 * @author Endi S. Dewata
 */
public class SchemaReader {

    public Logger log = LoggerFactory.getLogger(getClass());

    public SchemaReader() {
    }

    public Schema read(File path) throws Exception {

        log.debug("Loading schema "+path+".");

        String fileName = path.getName();
        int i = fileName.lastIndexOf(".");
        String name = i < 0 ? fileName : fileName.substring(0, i);
        
        Schema schema = new Schema(name);

        if (!path.exists()) return schema;

        FileReader in = new FileReader(path);
        
        SchemaParser parser = new SchemaParser(in);
        Schema s = parser.parse();
        schema.add(s);

        return schema;
    }
}
