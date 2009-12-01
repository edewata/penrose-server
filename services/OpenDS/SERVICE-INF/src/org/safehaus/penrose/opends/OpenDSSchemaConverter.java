package org.safehaus.penrose.opends;

import org.safehaus.penrose.schema.AttributeType;
import org.safehaus.penrose.schema.ObjectClass;
import org.safehaus.penrose.schema.Schema;
import org.safehaus.penrose.schema.SchemaParser;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * @author Endi S. Dewata
 */
public class OpenDSSchemaConverter {

    public void convert(String input, String output) throws Exception {

        FileReader in = new FileReader(input);

        SchemaParser parser = new SchemaParser(in);
        Schema schema = parser.parse();

        PrintWriter out = new PrintWriter(new FileWriter(output), true);
        out.println("dn: cn=schema");
        out.println("objectClass: top");
        out.println("objectClass: ldapSubentry");
        out.println("objectClass: subschema");

        for (AttributeType at : schema.getAttributeTypes()) {
            out.println("attributeTypes: ( "+at+" )");
        }

        for (ObjectClass oc : schema.getObjectClasses()) {
            out.println("objectClasses: ( "+oc+" )");
        }

        out.close();
        in.close();
    }

    public static void main(String args[]) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: org.safehaus.penrose.opends.OpenDSSchemaConverter <input> <output>");
            System.exit(-1);
        }

        String input = args[0];
        String output = args[1];
        System.out.println("Converting generic LDAP schema: "+input);
        System.out.println("into OpenDS schema: "+output);

        OpenDSSchemaConverter converter = new OpenDSSchemaConverter();
        converter.convert(input, output);
    }
}
