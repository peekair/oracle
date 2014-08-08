
#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include "packet-oracle.h"

static int proto_oracle = -1;

static gint ett_oracle = -1;


static gboolean dissect_oracle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *oracle_tree;
    proto_tree  *ti;
    
    guint16 proto_len = 0;
    guint32 total_len = 0;
    
    total_len = tvb_reported_length(tvb);
    proto_len = tvb_get_ntohs(tvb,0);
    if(total_len != proto_len)
        return FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Oracle");

    if (tree) 
    {
        int  offset = 0;

        ti = proto_tree_add_item(tree, proto_oracle, tvb,   offset, -1, ENC_NA);
        oracle_tree = proto_item_add_subtree(ti, ett_oracle);

        
        guint8 pkt_type = 0;

        proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"Packet Length:%04X",tvb_get_ntohs(tvb,offset));
        offset += sizeof(guint16);

        proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"Packet Checksum:%04X",tvb_get_ntohs(tvb,offset));
        offset += sizeof(guint16);

        pkt_type = tvb_get_guint8(tvb,offset);
        proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8),"Packet Type:%02X",tvb_get_guint8(tvb,offset));
        offset += sizeof(guint8);       

        proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8),"Reserved:%02X",tvb_get_guint8(tvb,offset));
        offset += sizeof(guint8);

        proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"Header Checksum:%04X",tvb_get_ntohs(tvb,offset));
        offset += sizeof(guint16);

        

        switch(pkt_type)
        {
        case 0x01:
            col_set_str(pinfo->cinfo, COL_INFO, "Connect");
            //oracle_disp_0x01(oracle_tree,tvb,offset);
            break;
        case 0x06:
            col_set_str(pinfo->cinfo, COL_INFO, "Data");
            oracle_disp_0x06(oracle_tree,tvb,offset,pinfo);
            break;    
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "Unknown");
            break;
        }
    }

    return TRUE;
}

void oracle_disp_0x06(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset,packet_info *pinfo)
{
    gint total_len = tvb_reported_length(tvb);
    guint16 status = 0;
    guint16 cmd_id = 0;
    
    status = tvb_get_ntohs(tvb,offset);
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"Status:%04X",tvb_get_ntohs(tvb,offset));
    offset += sizeof(guint16);

    gint count = 0;

    while(offset < total_len)
    {
        proto_tree_add_text(oracle_tree,tvb,offset,0,"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-");
        count++;
        if(count > 5)
            break;

        cmd_id = tvb_get_ntohs(tvb,offset);
        
        switch(cmd_id)
        {
        case 0x0106:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0106=>SetProtocol");
            break;
        case 0x0254:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0254=>");
            break;
        case 0x0280:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0280=>");
            break;
        case 0x0305:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0305=>FeathMore");
            break;
        case 0x0309:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0309=>");
            break;
        case 0x030E:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x030E=>");
            break;
        case 0x035E:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x035E=>SQL");
            offset = oracle_cmd_0x035E(oracle_tree,tvb,offset);
            break;
        case 0x0373:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0373=>AUTH2");
            offset = oracle_cmd_0x0373(oracle_tree,tvb,offset);
            break;
        case 0x0376:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0376=>AUTH1");
            offset = oracle_cmd_0x0376(oracle_tree,tvb,offset);
            break;
        case 0x0401:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0401=>ACK");
            offset = oracle_cmd_0x0401(oracle_tree,tvb,offset);
            break;
        case 0x0601:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0601=>FirstRowResultInfo");
            break;
        case 0x0803:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0803=>");
            offset = oracle_cmd_0x0803(oracle_tree,tvb,offset);
            break;
        case 0x0806:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0806=>");
            break;
        case 0x0819:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0819=>");
            offset = oracle_cmd_0x0819(oracle_tree,tvb,offset);
            break;
        case 0x089A:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x089A=>");
            break;
        case 0x0905:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0905=>");
            break;
        case 0x0B01:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x0B01=>");
            break;
        case 0x1017:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x1017=>");
            break;
        case 0x1169:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x1169=>");
            offset = oracle_cmd_0x1169(oracle_tree,tvb,offset);
            break;
        case 0x116B:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0x116B=>");

            break;
        case 0xDEAD:
            col_set_str(pinfo->cinfo, COL_INFO, "Data->0xDEAD=>");
            break;
        default:
            break;
        }
    }
}

gint oracle_cmd_0x035E(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset)
{
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"cmd id:%04X",tvb_get_ntohs(tvb,offset));
    offset += sizeof(guint16);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8),"Sequence:%02X",tvb_get_guint8(tvb,offset));
    offset += sizeof(guint8);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V00:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V01:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V02:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V03:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V04:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V05:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V06:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V07:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V08:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V09:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V0A:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V0B:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V0C:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V0D:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V0E:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V0F:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V10:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V11:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V12:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V13:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V14:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V15:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V16:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V17:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    return offset;
}


gint oracle_cmd_0x0373(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset)
{
    guint64 item_count = 0;
    guint64 i = 0;

    guint8 nstr_len = 0;

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"cmd id:%04X",tvb_get_ntohs(tvb,offset));
    offset += sizeof(guint16);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8),"seq id:%02X",tvb_get_guint8(tvb,offset));
    offset += sizeof(guint8);

    proto_tree_add_text(oracle_tree,tvb,offset,2*sizeof(guint64),"F1:%016X",tvb_get_letoh64(tvb,offset+sizeof(guint64)));
    offset += 2*sizeof(guint64);

    item_count = tvb_get_letoh64(tvb,offset+sizeof(guint64));
    proto_tree_add_text(oracle_tree,tvb,offset,2*sizeof(guint64),"F2:%016X",tvb_get_letoh64(tvb,offset+sizeof(guint64)));
    offset += 2*sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,2*sizeof(guint64),"F3:%016X",tvb_get_letoh64(tvb,offset+sizeof(guint64)));
    offset += 2*sizeof(guint64);

    nstr_len = tvb_get_guint8(tvb,offset);
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8)+nstr_len,"root:%s",tvb_get_string(tvb,offset+sizeof(guint8),nstr_len));
    offset += sizeof(guint8)+nstr_len;

    for(i = 0; i < item_count; i++)
    {
        guint32 field_4len = 0;
        guint32 value_4len = 0;
        guint8  field_1len = 0;
        guint8  value_1len = 0;
        gint    field_data = 0;
        gint    value_data = 0;
        gint    curpos = 0;
        gint    movlen = 0;

        char    xdata_buf[0x2000];
        guint32 xdata_len = 0;

        curpos = offset; movlen = 0;
        field_4len = tvb_get_letohl(tvb,curpos);
        curpos += sizeof(guint32);  
        movlen += sizeof(guint32);

        //field
        field_1len = tvb_get_guint8(tvb,curpos);
         if(field_1len == 0xFE)
        {
            curpos += 2*sizeof(guint8); 
            movlen += 2*sizeof(guint8);
        }
        else
        {
            curpos += sizeof(guint8); 
            movlen += sizeof(guint8);
        }
        field_data = curpos;                    
        curpos += field_4len;       
        movlen += field_4len;
    
        //value
        value_4len = tvb_get_letohl(tvb,curpos);
        curpos += sizeof(guint32);
        movlen += sizeof(guint32);

        value_1len = tvb_get_guint8(tvb,curpos);
        if(value_1len == 0xFE)
        {
            curpos += sizeof(guint8);
            movlen += sizeof(guint8);

            while(1)
            {
                value_1len = tvb_get_guint8(tvb,curpos);
                curpos += sizeof(guint8);
                movlen += sizeof(guint8);
                if(value_1len == 0x00)
                    break;
                if(xdata_len <= 0x80)
                {
                    tvb_memcpy(tvb,xdata_buf+xdata_len,curpos,value_1len);
                }
                else
                {
                    xdata_buf[0x80] = 0;
                }
                curpos += value_1len;
                movlen += value_1len;
                xdata_len += value_1len;
            }
            xdata_buf[xdata_len] = 0;
        }
        else
        {
            curpos += sizeof(guint8); 
            movlen += sizeof(guint8);

            tvb_memcpy(tvb,xdata_buf,curpos,value_1len);
            xdata_len += value_1len;
            xdata_buf[xdata_len] = 0;
            curpos += value_1len;
            movlen += value_1len;
            xdata_len += value_1len;
        }
        value_data = curpos;                    
        //curpos += value_4len;       
        //movlen += value_4len;
        movlen += sizeof(guint32);

        proto_tree_add_text(oracle_tree,tvb,offset,movlen,"[%02X]%s:%s",i,tvb_get_string(tvb,field_data,field_4len),xdata_buf);
        offset += movlen; 
    }

    return offset;
}

gint oracle_cmd_0x0376(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset)
{
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"cmd id:%04X",tvb_get_ntohs(tvb,offset));
    offset += sizeof(guint16);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8),"seq id:%02X",tvb_get_guint8(tvb,offset));
    offset += sizeof(guint8);

    //proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V00:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    //guint64 item_count = 0;
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V01:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V02:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    guint64 item_count = 0;
    guint64 i = 0;
    item_count = tvb_get_letoh64(tvb,offset);
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V03:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V04:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V05:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    guint8 nstr_len = 0;
    nstr_len = tvb_get_guint8(tvb,offset);
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8)+nstr_len,"root:%s",tvb_get_string(tvb,offset+sizeof(guint8),nstr_len));
    offset += sizeof(guint8)+nstr_len;

    for(i = 0; i < item_count; i++)
    {
        guint32 field_4len = 0;
        guint32 value_4len = 0;
        guint8  field_1len = 0;
        guint8  value_1len = 0;
        gint    field_data = 0;
        gint    value_data = 0;
        gint    curpos = 0;
        gint    movlen = 0;

        char    xdata_buf[0x2000];
        guint32 xdata_len = 0;

        curpos = offset; movlen = 0;
        field_4len = tvb_get_letohl(tvb,curpos);
        curpos += sizeof(guint32);  
        movlen += sizeof(guint32);

        //field
        field_1len = tvb_get_guint8(tvb,curpos);
         if(field_1len == 0xFE)
        {
            curpos += 2*sizeof(guint8); 
            movlen += 2*sizeof(guint8);
        }
        else
        {
            curpos += sizeof(guint8); 
            movlen += sizeof(guint8);
        }
        field_data = curpos;                    
        curpos += field_4len;       
        movlen += field_4len;
    
        //value
        value_4len = tvb_get_letohl(tvb,curpos);
        curpos += sizeof(guint32);
        movlen += sizeof(guint32);

        value_1len = tvb_get_guint8(tvb,curpos);
        if(value_1len == 0xFE)
        {
            curpos += sizeof(guint8);
            movlen += sizeof(guint8);

            while(1)
            {
                value_1len = tvb_get_guint8(tvb,curpos); 
                curpos += sizeof(guint8);
                movlen += sizeof(guint8);
                if(value_1len == 0x00)
                    break;
                if(xdata_len <= 0x80)
                {
                    tvb_memcpy(tvb,xdata_buf+xdata_len,curpos,value_1len);
                }
                else
                {
                    xdata_buf[0x80] = 0;
                }
                curpos += value_1len;
                movlen += value_1len;
                xdata_len += value_1len;
            }
            xdata_buf[xdata_len] = 0;
        }
        else
        {
            curpos += sizeof(guint8); 
            movlen += sizeof(guint8);

            tvb_memcpy(tvb,xdata_buf,curpos,value_1len);
            xdata_len += value_1len;
            xdata_buf[xdata_len] = 0;
            curpos += value_1len;
            movlen += value_1len;
            xdata_len += value_1len;
        }
        value_data = curpos;                    
        //curpos += value_4len;       
        //movlen += value_4len;
        movlen += sizeof(guint32);

        proto_tree_add_text(oracle_tree,tvb,offset,movlen,"[%02X]%s:%s",i,tvb_get_string(tvb,field_data,field_4len),xdata_buf);
        offset += movlen; 
    }

    return offset;
}

gint oracle_cmd_0x0401(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset)
{

}

gint oracle_cmd_0x0803(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset)
{
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"cmd id:%04X",tvb_get_ntohs(tvb,offset));
    offset += sizeof(guint16);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8),"seq id:%02X",tvb_get_guint8(tvb,offset));
    offset += sizeof(guint8);

    gint item_count = 3;
    gint i = 0;
    for(i = 0; i < item_count; i++)
    {
        guint32 field_4len = 0;
        guint32 value_4len = 0;
        guint8  field_1len = 0;
        guint8  value_1len = 0;
        gint    field_data = 0;
        gint    value_data = 0;
        gint    curpos = 0;
        gint    movlen = 0;

        char    xdata_buf[0x2000];
        guint32 xdata_len = 0;

        curpos = offset; movlen = 0;
        field_4len = tvb_get_letohl(tvb,curpos);
        curpos += sizeof(guint32);  
        movlen += sizeof(guint32);

        //field
        field_1len = tvb_get_guint8(tvb,curpos);
         if(field_1len == 0xFE)
        {
            curpos += 2*sizeof(guint8); 
            movlen += 2*sizeof(guint8);
        }
        else
        {
            curpos += sizeof(guint8); 
            movlen += sizeof(guint8);
        }
        field_data = curpos;                    
        curpos += field_4len;       
        movlen += field_4len;
    
        //value
        value_4len = tvb_get_letohl(tvb,curpos);
        curpos += sizeof(guint32);
        movlen += sizeof(guint32);

        value_1len = tvb_get_guint8(tvb,curpos);
        if(value_1len == 0xFE)
        {
            curpos += sizeof(guint8);
            movlen += sizeof(guint8);

            while(1)
            {
                value_1len = tvb_get_guint8(tvb,curpos); 
                curpos += sizeof(guint8);
                movlen += sizeof(guint8);
                if(value_1len == 0x00)
                    break;
                if(xdata_len <= 0x80)
                {
                    tvb_memcpy(tvb,xdata_buf+xdata_len,curpos,value_1len);
                }
                else
                {
                    xdata_buf[0x80] = 0;
                }
                curpos += value_1len;
                movlen += value_1len;
                xdata_len += value_1len;
            }
            xdata_buf[xdata_len] = 0;
        }
        else
        {
            curpos += sizeof(guint8); 
            movlen += sizeof(guint8);

            tvb_memcpy(tvb,xdata_buf,curpos,value_1len);
            xdata_len += value_1len;
            xdata_buf[xdata_len] = 0;
            curpos += value_1len;
            movlen += value_1len;
            xdata_len += value_1len;
        }
        value_data = curpos;                    
        //curpos += value_4len;       
        //movlen += value_4len;
        movlen += sizeof(guint32);

        proto_tree_add_text(oracle_tree,tvb,offset,movlen,"[%02X]%s:%s",i,tvb_get_string(tvb,field_data,field_4len),xdata_buf);
        offset += movlen; 
    }

    return offset;
}


gint oracle_cmd_0x0819(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset)
{
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"cmd id:%04X",tvb_get_ntohs(tvb,offset));
    offset += sizeof(guint16);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8),"seq id:%02X",tvb_get_guint8(tvb,offset));
    offset += sizeof(guint8);

    gint item_count = 16;
    gint i = 0;
    for(i = 0; i < item_count; i++)
    {
        guint32 field_4len = 0;
        guint32 value_4len = 0;
        guint8  field_1len = 0;
        guint8  value_1len = 0;
        gint    field_data = 0;
        gint    value_data = 0;
        gint    curpos = 0;
        gint    movlen = 0;

        char    xdata_buf[0x2000];
        guint32 xdata_len = 0;

        curpos = offset; movlen = 0;
        field_4len = tvb_get_letohl(tvb,curpos);
        curpos += sizeof(guint32);  
        movlen += sizeof(guint32);

        //field
        field_1len = tvb_get_guint8(tvb,curpos);
         if(field_1len == 0xFE)
        {
            curpos += 2*sizeof(guint8); 
            movlen += 2*sizeof(guint8);
        }
        else
        {
            curpos += sizeof(guint8); 
            movlen += sizeof(guint8);
        }
        field_data = curpos;                    
        curpos += field_4len;       
        movlen += field_4len;
    
        //value
        value_4len = tvb_get_letohl(tvb,curpos);
        curpos += sizeof(guint32);
        movlen += sizeof(guint32);

        value_1len = tvb_get_guint8(tvb,curpos);
        if(value_1len == 0xFE)
        {
            curpos += sizeof(guint8);
            movlen += sizeof(guint8);

            while(1)
            {
                value_1len = tvb_get_guint8(tvb,curpos); 
                curpos += sizeof(guint8);
                movlen += sizeof(guint8);
                if(value_1len == 0x00)
                    break;
                if(xdata_len <= 0x80)
                {
                    tvb_memcpy(tvb,xdata_buf+xdata_len,curpos,value_1len);
                }
                else
                {
                    xdata_buf[0x80] = 0;
                }
                curpos += value_1len;
                movlen += value_1len;
                xdata_len += value_1len;
            }
            xdata_buf[xdata_len] = 0;
        }
        else
        {
            curpos += sizeof(guint8); 
            movlen += sizeof(guint8);

            tvb_memcpy(tvb,xdata_buf,curpos,value_1len);
            xdata_len += value_1len;
            xdata_buf[xdata_len] = 0;
            curpos += value_1len;
            movlen += value_1len;
            xdata_len += value_1len;
        }
        value_data = curpos;                    
        //curpos += value_4len;       
        //movlen += value_4len;
        movlen += sizeof(guint32);

        proto_tree_add_text(oracle_tree,tvb,offset,movlen,"[%02X]%s:%s",i,tvb_get_string(tvb,field_data,field_4len),xdata_buf);
        offset += movlen; 
    }

    return offset;
}

gint oracle_cmd_0x1169(proto_tree *oracle_tree,tvbuff_t *tvb,gint offset)
{
    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint16),"cmd id:%04X",tvb_get_ntohs(tvb,offset));
    offset += sizeof(guint16);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint8),"Sequence:%02X",tvb_get_guint8(tvb,offset));
    offset += sizeof(guint8);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V00:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint64),"V01:%016X",tvb_get_letoh64(tvb,offset));
    offset += sizeof(guint64);

    proto_tree_add_text(oracle_tree,tvb,offset,sizeof(guint32),"X:%08X",tvb_get_letohl(tvb,offset));
    offset += sizeof(guint32); 

    return offset;   
}

void proto_register_oracle(void)
{
    static hf_register_info hf[] = {};
    static gint *ett[] = {&ett_oracle,};

    proto_oracle = proto_register_protocol("Oracle Protocol","Oracle", "oracle");

    proto_register_field_array(proto_oracle, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_oracle(void)
{
    dissector_handle_t oracle_handle;

    oracle_handle = new_create_dissector_handle(dissect_oracle, proto_oracle);
    dissector_add_uint("tcp.port", 1521, oracle_handle);
}