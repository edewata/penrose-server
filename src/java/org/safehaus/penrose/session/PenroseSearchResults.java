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
package org.safehaus.penrose.session;

import org.ietf.ldap.LDAPException;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Collection;
import java.util.Iterator;

/**
 * @author Endi S. Dewata
 */
public class PenroseSearchResults implements Iterator {

    public Logger log = Logger.getLogger(getClass());

    public List results = new ArrayList();
    public boolean done = false;

    private int returnCode = LDAPException.SUCCESS;
    
    public synchronized void add(Object object) {
        results.add(object);
        notifyAll();
    }

    public synchronized void addAll(Collection collection) {
        results.addAll(collection);
        notifyAll();
    }

    public synchronized boolean hasNext() {
        while (!done && results.size() == 0) {
            try {
                wait();
            } catch (Exception e) {
                e.printStackTrace(System.out);
            }
        }

        return results.size() > 0;
    }

    public synchronized Object next() {
        while (!done && results.size() == 0) {
            try {
                wait();
            } catch (Exception e) {
                e.printStackTrace(System.out);
            }
        }

        if (results.size() == 0) return null;

        return results.remove(0);
    }

    public synchronized void close() {
        done = true;
        notifyAll();
    }

    public synchronized Collection getAll() {
        while (!done) {
            try {
                wait();
            } catch (Exception e) {
                e.printStackTrace(System.out);
            }
        }

        return results;
    }

    public synchronized int size() {
        while (!done) {
            try {
                wait();
            } catch (Exception e) {
                e.printStackTrace(System.out);
            }
        }

        return results.size();
    }

    public Iterator iterator() {
        return this;
    }

    public synchronized int getReturnCode() {
        while (!done) {
            try {
                wait();
            } catch (Exception e) {
                e.printStackTrace(System.out);
            }
        }

        return returnCode;
    }

    public void remove() {
    }

    public void setReturnCode(int returnCode) {
        this.returnCode = returnCode;
    }

    public boolean isClosed() {
        return done;
    }
}