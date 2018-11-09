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



/* Register the protocol with Wireshark
/* this format is required because a script is used to build
/* the C function that calls all the protocol registration.
*/
void proto_register_ETI(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
	{ &hf_ETI_BodyLen,
	{ "Body Length",
	"ETI.BodyLen",
	FT_UINT32, BASE_DEC, NULL, 0x0, "Length of the Body of the Message.", HFILL }
	},

	{ &hf_ETI_TemplateID,
	{ "Template ID",
	"ETI.TemplateID",
	FT_UINT32, BASE_DEC, NULL, 0x0, "Template ID of the message.", HFILL }
	},

	{ &hf_ETI_NetworkingMsgID,
	{ "Networking Message ID",
	"ETI.NetworkingMsgID",
	FT_STRING, BASE_DEC, NULL, 0x0, "Networking Message ID of the message.", HFILL }
	},
	};
	/* Setup protocol subtree array */
	static gint *ett[] = {
	&ett_ETI,
	};
	/* Register the protocol name and description */
	proto_ETI = proto_register_protocol(“Eurex_Enhanced_Trading_Interface”, “Eurex_ETI”, “ETI”, HFILL);

	/* Required function calls to register the header fields and subtree used */
	proto_register_field_array(proto_ETI, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

//Handoff for the protocol dissector
void proto_reg_handoff_ETI(void)
{
	dissector_handle_t ETI_handle;
	ETI_handle = create_dissector_handle(dissect_ETI, proto_ETI);
	//22 TCP port just added for reference. Needs to be changed.
	dissector_add(“tcp.port”, 22, ETI_handle);
}
