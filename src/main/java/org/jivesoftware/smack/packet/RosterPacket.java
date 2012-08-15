/**
 * $RCSfile$
 * $Revision: 9548 $
 * $Date: 2007-12-02 18:00:03 -0600 (Sun, 02 Dec 2007) $
 *
 * Copyright 2003-2007 Jive Software.
 *
 * All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.smack.packet;

import org.jivesoftware.smack.RosterEntry;
import org.jivesoftware.smack.util.StringUtils;

import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Represents XMPP roster packets.
 *
 * @author Matt Tucker
 */
public class RosterPacket extends IQ {

    private final List<Item> rosterItems = new ArrayList<Item>();

    /**
     * Adds a roster item to the packet.
     *
     * @param item a roster item.
     */
    public void addRosterItem(Item item) {
        synchronized (rosterItems) {
            rosterItems.add(item);
        }
    }

    /**
     * Returns the number of roster items in this roster packet.
     *
     * @return the number of roster items.
     */
    public int getRosterItemCount() {
        synchronized (rosterItems) {
            return rosterItems.size();
        }
    }

    /**
     * Returns an unmodifiable collection for the roster items in the packet.
     *
     * @return an unmodifiable collection for the roster items in the packet.
     */
    public Collection<Item> getRosterItems() {
        synchronized (rosterItems) {
            return Collections.unmodifiableList(new ArrayList<Item>(rosterItems));
        }
    }

    public String getChildElementXML() {
        StringBuilder buf = new StringBuilder();
        //buf.append("<query xmlns=\"jabber:iq:roster\">");
        buf.append("<query xmlns=\"jabber:iq:roster\" xmlns:gr=\"google:roster\" gr:ext=\"2\">");
        synchronized (rosterItems) {
            for (Item entry : rosterItems) {
                buf.append(entry.toXML());
            }
        }
        buf.append("</query>");
        return buf.toString();
    }

    /**
     * A roster item, which consists of a JID, their name, the type of subscription, and
     * the groups the roster item belongs to.
     */
    public static class Item {

        private final String user;
        private String name;
        private ItemType itemType;
        private ItemStatus itemStatus;
        private final Set<String> groupNames;
        
        private final int mc;
        
        private final int emc;
        
        private final int w;
        
        private final boolean rejected;
        
        private final String t;
        
        private final boolean autosub;
        
        private final String aliasFor;
        
        private final String inv;
        
        public Item(final String user, final String name, 
            final ItemType itemType, final ItemStatus itemStatus, final int mc, 
            final int emc, final int w, final boolean rejected, final String t, 
            final boolean autosub, final String aliasFor, final String inv) {
            this.user = user.toLowerCase();
            this.name = name;
            this.itemType = itemType;
            this.itemStatus = itemStatus;
            this.mc = mc;
            this.emc = emc;
            this.w = w;
            this.rejected = rejected;
            this.t = t;
            this.autosub = autosub;
            this.aliasFor = aliasFor;
            this.inv = inv;
            this.groupNames = new CopyOnWriteArraySet<String>();
        }

        public Item(final RosterEntry entry) {
            this(entry.getUser(), entry.getName(), entry.getType(), 
                entry.getStatus(), entry.getMc(), entry.getEmc(), entry.getW(),
                entry.isRejected(), entry.getT(), entry.isAutosub(),
                entry.getAliasFor(), entry.getInv());
            //this.groupNames = new CopyOnWriteArraySet<String>();
        }

        /**
         * Creates a new roster item.
         *
         * @param user the user.
         * @param name the user's name.
         */
        /*
        public Item(String user, String name) {
            this.user = user.toLowerCase();
            this.name = name;
            itemType = null;
            itemStatus = null;
            groupNames = new CopyOnWriteArraySet<String>();
        }
        */

        public int getMc() {
            return mc;
        }

        public int getEmc() {
            return emc;
        }

        public int getW() {
            return w;
        }

        public boolean isRejected() {
            return rejected;
        }

        public String getT() {
            return t;
        }

        public boolean isAutosub() {
            return autosub;
        }

        public String getAliasFor() {
            return aliasFor;
        }

        public String getInv() {
            return inv;
        }

        /**
         * Returns the user.
         *
         * @return the user.
         */
        public String getUser() {
            return user;
        }

        /**
         * Returns the user's name.
         *
         * @return the user's name.
         */
        public String getName() {
            return name;
        }

        /**
         * Sets the user's name.
         *
         * @param name the user's name.
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * Returns the roster item type.
         *
         * @return the roster item type.
         */
        public ItemType getItemType() {
            return itemType;
        }

        /**
         * Sets the roster item type.
         *
         * @param itemType the roster item type.
         */
        public void setItemType(ItemType itemType) {
            this.itemType = itemType;
        }

        /**
         * Returns the roster item status.
         *
         * @return the roster item status.
         */
        public ItemStatus getItemStatus() {
            return itemStatus;
        }

        /**
         * Sets the roster item status.
         *
         * @param itemStatus the roster item status.
         */
        public void setItemStatus(ItemStatus itemStatus) {
            this.itemStatus = itemStatus;
        }

        /**
         * Returns an unmodifiable set of the group names that the roster item
         * belongs to.
         *
         * @return an unmodifiable set of the group names.
         */
        public Set<String> getGroupNames() {
            return Collections.unmodifiableSet(groupNames);
        }

        /**
         * Adds a group name.
         *
         * @param groupName the group name.
         */
        public void addGroupName(String groupName) {
            groupNames.add(groupName);
        }

        /**
         * Removes a group name.
         *
         * @param groupName the group name.
         */
        public void removeGroupName(String groupName) {
            groupNames.remove(groupName);
        }

        public String toXML() {
            StringBuilder buf = new StringBuilder();
            buf.append("<item jid=\"").append(user).append("\"");
            if (name != null) {
                buf.append(" name=\"").append(StringUtils.escapeForXML(name)).append("\"");
            }
            if (itemType != null) {
                buf.append(" subscription=\"").append(itemType).append("\"");
            }
            if (itemStatus != null) {
                buf.append(" ask=\"").append(itemStatus).append("\"");
            }
            buf.append(">");
            for (String groupName : groupNames) {
                buf.append("<group>").append(StringUtils.escapeForXML(groupName)).append("</group>");
            }
            buf.append("</item>");
            return buf.toString();
        }
    }

    /**
     * The subscription status of a roster item. An optional element that indicates
     * the subscription status if a change request is pending.
     */
    public static class ItemStatus {

        /**
         * Request to subcribe.
         */
        public static final ItemStatus SUBSCRIPTION_PENDING = new ItemStatus("subscribe");

        /**
         * Request to unsubscribe.
         */
        public static final ItemStatus UNSUBSCRIPTION_PENDING = new ItemStatus("unsubscribe");

        public static ItemStatus fromString(String value) {
            if (value == null) {
                return null;
            }
            value = value.toLowerCase();
            if ("unsubscribe".equals(value)) {
                return UNSUBSCRIPTION_PENDING;
            }
            else if ("subscribe".equals(value)) {
                return SUBSCRIPTION_PENDING;
            }
            else {
                return null;
            }
        }

        private String value;

        /**
         * Returns the item status associated with the specified string.
         *
         * @param value the item status.
         */
        private ItemStatus(String value) {
            this.value = value;
        }

        public String toString() {
            return value;
        }
    }

    public static enum ItemType {

        /**
         * The user and subscriber have no interest in each other's presence.
         */
        none,

        /**
         * The user is interested in receiving presence updates from the subscriber.
         */
        to,

        /**
         * The subscriber is interested in receiving presence updates from the user.
         */
        from,

        /**
         * The user and subscriber have a mutual interest in each other's presence.
         */
        both,

        /**
         * The user wishes to stop receiving presence updates from the subscriber.
         */
        remove
    }
}
