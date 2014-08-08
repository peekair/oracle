
#include <epan/packet.h>

void oracle_disp_0x06(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset,packet_info *pinfo);
gint oracle_cmd_0x035E(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset);
gint oracle_cmd_0x0373(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset);
gint oracle_cmd_0x0376(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset);
gint oracle_cmd_0x0401(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset);
gint oracle_cmd_0x0803(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset);
gint oracle_cmd_0x0819(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset);
gint oracle_cmd_0x1169(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset);