#include "config.h"

#include <epan/packet.h>

#define WRSOCKET_PORT 9999

static int proto_wrsocket = -1;

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
}

void
proto_reg_handoff_wrsocket(void)
{
	static_dissector_handle_t wrsocket_handle;
	
	wrsocket_handle = create_dissector_handle(dissect_wrsocket, proto_wrsocket);//handler associates proto with dissector
	dissector_add_uint("tcp.port", WRSOCKET_PORT, wrsocket_handle); //associate port with handler
}

static int
dissect_wrsocket(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WRSOCKET");
	col_clear(pinfo->cinfog, COL_INFO);
	
	return tvb_captured_length(tvb);
}

