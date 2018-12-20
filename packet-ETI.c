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
wmem_allocator *scope;
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
		hf_ETI_BodyLen = tvb_get_letohl(tvb, offset);
		proto_tree_add_int(eti_tree, hf_ETI_BodyLen, tvb, offset, 4,ENC_LITTLE_ENDIAN);
		offset+=4;
		hf_ETI_TemplateID = tvb_get_letohs(tvb, offset);
		proto_tree_add_int(eti_tree, hf_ETI_TemplateID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset+=2;
		switch(hf:ETI_TemplateID)
		{
			case 10020:{
				hf_ETI_NetworkMsgID = tvb_get_string_enc(scope, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(eti_tree, hf_ETI_NetworkMsgID, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset+=8;
				hf_ETI_Pad2 = tvb_get_string_enc(scope, tvb, oddset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(eti_tree, hf_ETI_Pad2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset+=2;
				hf_ETI_MsgSeqNum = tvb_get_letohl(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI,MsgSeqNum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset+=4;
				hf_ETI_SenderSubID = tvb_get_letohl(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_SenderSubID, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset+=4;
				hf_ETI_PartyIDSessionID = tvb_get_letohl(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_PartyIDSessionID, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset+=4;
				hf_ETI_DefaultCstmApplVerID = tvb_get_string_enc(scope, tvb, offset, 30, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(eti_tree, hf_ETI_DefaultCstmApplVerID, tvb, offset, 30, ENC_LITTLE_ENDIAN);
				offset+=30;
				hf_ETI_Password = tvb_get_string_enc(scope, tvb, offset, 32, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(eti_tree, hf_ETI_Password, tvb, offset, 32, ENC_LITTLE_ENDIAN);
				offset+=32;
				break;
			}
			case 10021:{
				hf_ETI_Pad2 = tvb_get_string_enc(scope, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(eti_tree, hf_ETI_Pad2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset+=2;
				hf_ETI_RequestTime = tvb_get_ts_23_038_7bits_string(scope, tvb, offset, 8);
				proto_tree_add_time(eti_tree, hf_ETI_RequestTime, tvb, offset, 8, value_ptr);
				offset+=8;
				hf_ETI_SendingTime = tvb_get_ts_23_038_7bits_string(scope, tvb, offset, 8);
				proto_tree_add_time(eti_tree, hf_ETI_SendingTime, tvb, offset, 8, value_ptr);
				hf_ETI_MsgSeqNum = tvb_get_letohl(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI,MsgSeqNum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset+=4;
				hf_ETI_Pad4 = tvb_get_string_enc(scope, tvb, oddset, 4, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(eti_tree, hf_ETI_Pad4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset+=4;
				hf_ETI_GatewayID = tvb_get_letohl(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_GatewayID, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset+=4;
				hf_ETI_GatewaySubID = tvb_get_letohl(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_GatewaySubID, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset+=4;
				hf_ETI_SecondaryGatewayID = tvb_get_letohl(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_SecondaryGatewayID, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset+=4;
				hf_ETI_SecondaryGatewaySubID = tvb_get_letohl(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_SecondaryGatewaySubID, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset+=4;
				hf_ETI_GatewayStatus = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_GatewayStatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset++;
				hf_ETI_SecondaryGatewayStatus = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_SecondaryGatewayStatus, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset++;
				hf_ETI_SessionMode = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_SessionMode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset++;
				hf_ETI_TradeSesMode = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint(eti_tree, hf_ETI_TradeSesMode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset++;
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
	},
	{
		&hf_ETI_RequestTime,
		{
			"RequestTime",
			"ETI.RequestTime",
			FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0, "RequestTime", HFILL
		}
	},
	{
		&hf_ETI_SendingTime,
		{
			"SendingTime", 
			"ETI.SendingTime",
			FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0, "SendingTime", HFILL
		}
	},
	{
		&hf_ETI_Pad4,
		{
			"Pad4",
			"ETI.Pad4",
			FT_STRING, BASE_NONE, NULL, 0x0, "Padding", HFILL
		}
	},
	{
		&hf_ETI_GatewayID, 
		{
			"GatewayID",
			"ETI.GatewayID",
			FT_UINT32, BASE_DEC, NULL, 0x0, "GatewayID", HFILL
		}
	},
	{
		&hf_ETI_GatewaySubID,
		{
			"GatewaySubID",
			"ETI.GatewaySubID",
			FT_UINT32, BASE_DEC, NULL, 0x0, "GatewaySubID", HFILL
		}
	},
	{
		&hf_ETI_SecondaryGatewayID,
		{
			"SecondaryGatewayID",
			"ETI.SecondaryGatewayID",
			FT_UINT32, BASE_DEC, NULL, 0x0, "SecondaryGatewayID", HFILL
		}
	},
	{
		&hf_ETI_SecondaryGatewaySubID,
		{
			"SecondaryGatewaySubID",
			"ETI.SecondaryGatewaySubID",
			FT_UINT32, BASE_DEC, NULL, 0x0, "SecondaryGatewaySubID", HFILL
		}
	},
	{
		&hf_ETI_GatewayStatus,
		{
			"GatewayStatus",
			"ETI.GatewayStatus",
			FT_UINT8, BASE_DEC, NULL, 0x0, "GatewayStatus", HFILL
		}
	},
	{
		&hf_ETI_SecondaryGatewayStatus,
		{
			"SecondaryGatewayStatus",
			"ETI.SecondaryGatewayStatus",
			FT_UINT8, BASE_DEC, NULL, 0x0, "SecondaryGatewayStatus", HFILL
		}
	},
	{
		&hf_ETI_SessionMode,
		{
			"SessionMode",
			"ETI.SessionMode",
			FT_UINT8, BASE_DEC, NULL, 0x0, "SessionMode", HFILL
		}
	},
	{
		&hf_ETI_TradeSesMode,
		{
			"TradeSesMode",
			"ETI.TradeSesMode",
			FT_UINT8, BASE_DEC, NULL, 0x0, "TradeSesMode", HFILL
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
