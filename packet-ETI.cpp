/* packet-ETI.cpp
 * Routines for EUREX ETI dissection
 * Copyright 2018, DHARMANG BHAVSAR <dharmangb@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *																									
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/stat.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/column-info.h>
#include <epan/framedata.h>
#include <epan/packet-info.h>
#include <epan/value_string.h>

#include "ETILayoutsNS_Derivatives.h"

void proto_register_ETI(void);
void proto_reg_handoff_ETI(void);

/* Wireshark ID of the ETI protocol */
static int proto_ETI = -1;

/*The port ID on which the dissector works*/
static int global_ETI_port = 22;

static int hf_eti_pdu_type = -1;

static gint ett_eti = -1;
/*The main code to dissect the protocol*/
static int
dissect_eti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	static guint32 offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETI");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
	if(tree)
	{
		proto_item *ti = proto_tree_add_item(tree, proto_ETI, tvb, 0, -1, ENC_NA);
		proto_tree *eti_tree = NULL;
		guint8 offset = 0;
		eti_tree = proto_item_add_subtree(ti, ett_eti);
		hf_ETI_BodyLen = tvb_get_letohl(tvbuff_t *tvb, const gint offset);
		proto_tree_add_item(eti_tree, hf_ETI_BodyLen, tvb, offset, 1,ENC_LITTLE_ENDIAN);
		offset+=4;
		hf_ETI_TemplateID = tvb_get_letohs(tvbuff_t *tvb, const gint offset);
		proto_tree_add_item(eti_tree, hf_ETI_TemplateID, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset+=2;
		switch(hf:ETI_TemplateID)
		{
			case 10020:{
				hf_ETI_NetworkMsgID = tvb_get_string_enc(wmem_allocator_t *scope, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(eti_tree, hf_ETI_NetworkMsgID, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset+=8;
				hf_ETI_Pad2 = tvb_get_string_enc()

			}

		}
	}

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark
/* this format is required because a script is used to build
/* the C function that calls all the protocol registration.
*/
void proto_register_ETI(void)
{
	/* Setup list of header fields */
	/*We create a structure to register our fields. It consists of an
    * array of hf_register_info structures, each of which are of the format
    * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
    */
	static hf_register_info hf[] = {
	{ &hf_ETI_BodyLen,
	{ "Body Length", //Name
	"ETI.BodyLen", //Abbrev
	FT_UINT32,  //Type
	BASE_DEC,  //Display
	NULL, //Strings (What?)
	0x0, //Bitmask
	"Length of the Body of the Message.", //Blurb
	HFILL }
	},

	{ &hf_ETI_TemplateID,
		{ "Template ID",
		"ETI.TemplateID",
		FT_UINT32, BASE_DEC, NULL, 0x0, "Template ID of the message.", HFILL 
		}
	},

	{ &hf_ETI_NetworkMsgID,
		{ "Networking Message ID",
		"ETI.NetworkingMsgID",
		FT_STRING, BASE_NONE, NULL, 0x0, "Networking Message ID of the message.", HFILL 
		}
	},

	{
		&hf_ETI_Pad2,
		{
			"Padding",
			"ETI.Pad2",
			FT_STRING, BASE_NONE, NULL, 0x0, "Padding", HFILL
		}
	},

	{
		&hf_ETI_MsgSeqNum,
		{
			"Message Sequence Number",
			"ETI.MsgSeqNum", 
			FT_UINT32, BASE_DEC, NULL, 0x0, "Message Sequence Number of the Message.", HFILL
		}
	},

	{
		&hf_ETI_SenderSubID,
		{
			"Sender Sub ID",
			"ETI.SenderSubID",
			FT_UINT32, BASE_DEC, NULL, 0x0, "Sender Sub ID of the Message.", HFILL
		}
	},

	{
		&hf_ETI_PartyIDSessionID,
		{
			"Party ID Session ID",
			"ETI.PartyIDSessionID",
			FT_UINT32, BASE_DEC, NULL, 0x0, "Party ID Session ID of the Message.", HFILL 
		}
	},

	{
		&hf_ETI_PartitionID,
		{
			"Partition ID",
			"ETI.PartitionID",
			FT_UINT16, BASE_DEC, NULL, 0x0, "Partition ID", HFILL
		}
	},

	{
		&hf_ETI_DefaultCstmApplVerID,
		{
			"Default Customer Appliance Verification ID",
			"ETI.DefaultCstmApplVerID",
			FT_STRING, BASE_NONE, NULL, 0x0, "Default Customer Applicance Valudation ID", HFILL
		}
	},

	{
		&hf_ETI_Password,
		{
			"Password",
			"ETI.Password",
			FT_STRING, BASE_NONE, NULL, 0x0, "Password", HFILL
		}
	}
	};
	/* Setup protocol subtree array */
	static gint *ett[] = {
	&ett_eti,
	};	
	/* Register the protocol name and description */
	proto_ETI = proto_register_protocol("Eurex_Enhanced_Trading_Interface", "Eurex_ETI", "ETI", HFILL);

	/* Required function calls to register the header fields and subtree used */
	proto_register_field_array(proto_ETI, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
} 

//Handoff for the protocol dissector
void proto_reg_handoff_ETI(void)
{
	dissector_handle_t ETI_handle;
	ETI_handle = create_dissector_handle(dissect_ETI, proto_ETI);
	dissector_add("tcp.port", global_ETI_port, ETI_handle);
}
