#include "config.h"

#include <epan/packet.h>

#define WRSOCKET_PORT 9999

static int proto_wrsocket = -1;
static int hf_wrsocket_pdu_type = -1;
static gint ett_wrsocket = -1;


static int hf_wrsocket_flags = -1;
static int hf_wrsocket_sequenceno = -1;
static int hf_wrsocket_initialip = -1;


////https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html
//The standard Wireshark dissector convention is to put proto_register_wrsocket()
//and proto_reg_handoff_wrsocket() as the last two functions in the dissector source.
void
proto_register_wrsocket(void)
{
    proto_wrsocket = proto_register_protocol (
        "WRSOCKET Protocol", /* name       */
        "WRSOCKET",      /* short name */
        "wrsocket"       /* abbrev     */
        );

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_wrsocket
    };

// hf_foo_pdu_type - The index for this node.
// WRSOCKET PDU Type - The label for this item.
// wrsocket.type - This is the filter string. It enables us to type constructs such as foo.type=1 into the filter box.
// FT_UINT8 - This specifies this item is an 8bit unsigned integer. This tallies with our call above where we tell it to only look at one byte.
// BASE_DEC - For an integer type, this tells it to be printed as a decimal number. It could be hexadecimal (BASE_HEX) or octal (BASE_OCT) if that made more sense.

    static hf_register_info hf[] = {
    {
        &hf_wrsocket_pdu_type, {
                                  "WRSOCKET PDU Type",
                                  "wrsocket.type",
                        		  FT_UINT8, BASE_DEC,
                        		  NULL, 0x0,
                        		  NULL, HFILL
                               }
   }};


    proto_register_field_array(proto_wrsocket, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_wrsocket(void)
{
	static_dissector_handle_t wrsocket_handle;

	wrsocket_handle = create_dissector_handle(dissect_wrsocket, proto_wrsocket);	//handler associates proto with dissector
	dissector_add_uint("tcp.port", WRSOCKET_PORT, wrsocket_handle); 	//associate port with handler
}



// tvbuff_t *tvb : The packet data is held in this special buffer
// packet_info *pinfo: General data about the protocol, can be updated here
// proto_tree *tree:  is where the detail dissection takes place.
//
static int
dissect_wrsocket(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;

	col_clear(pinfo->cinfog, COL_INFO); // Clear data in info colum
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WRSOCKET"); //  set the text guilabel this to wrsocket protocol

	/*
		<proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);>

		What we’re doing here is adding a subtree to the dissection.
 		This subtree will hold all the details of this protocol and so not clutter up the display when not required.
		We are also marking the area of data that is being consumed by this protocol.
		In our case it’s all that has been passed to us, as we’re assuming this protocol does not encapsulate another.

		Add new tree node with proto_tree_add_item(),
	    Add it to the passed in tree, label it with the protocol,

		Pass tvb buffer as the data, and consume from 0 to the end (-1) of this data.
		ENC_NA ("not applicable") is specified as the "encoding" parameter.
	*/
	proto_item *ti = proto_tree_add_item(tree, proto_wrsocket, tvb, 0, -1, ENC_NA);

	//add a child node to the protocol tree which is where we will do our detail dissection.
    proto_tree *wrsocket_tree = proto_item_add_subtree(ti, ett_wrsocket);

	//Pick apart first bit of the protocol. One byte of data at the start of the packet that defines the packet type for foo protocol.
    proto_tree_add_item(wrsocket_tree, hf_wrsocket_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);

/*
 Dissects all the bits of this simple hypothetical protocol. We’ve introduced a new variable offsetinto the mix to help keep track of where we are in the packet dissection. With these extra bits in place, the whole protocol is now dissected.
*/
    offset += 1;
    proto_tree_add_item(foo_tree, hf_foo_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_tree, hf_foo_sequenceno, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(foo_tree, hf_foo_initialip, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

	return tvb_captured_length(tvb);
}
