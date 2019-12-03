/**************************************************************************************
 * Copyright (c) 2016, Tomoaki Yamaguchi
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Tomoaki Yamaguchi - initial API and implementation and/or initial documentation
 *    Tieto Poland Sp. z o.o. - Gateway improvements
 **************************************************************************************/

#include "MQTTSNGWPublishHandler.h"
#include "MQTTSNGWPacket.h"
#include "MQTTGWPacket.h"
#include "MQTTSNGateway.h"
#include "MQTTSNGWClient.h"
#include "MQTTSNGWQoSm1Proxy.h"
#include <string.h>
#include "aes.hpp"
using namespace std;
using namespace MQTTSNGW;

MQTTSNPublishHandler::MQTTSNPublishHandler(Gateway* gateway)
{
	_gateway = gateway;
}

MQTTSNPublishHandler::~MQTTSNPublishHandler()
{

}

static int pkcs7_remove_padding(uint8_t * buf, int len){
    uint8_t count;

    count = buf[len-1];

    if(len<=16 || (count > len)){
    	return len;
    }

    // printf("removing count = %u from len = %u\n", count, len);

    while(count){
        buf[len-1] = 0; // replace padding number with 0
        len--;
        count--;
    }

    return len;
}

static int decrypt_pkt_payload(uint8_t *buf, int len){
    // AES128 encryption
    // int i;
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, buf, len);

    // printf("\necrypted buffer with padding: ");

    // for(i = 0; i < len; i++){
    // 	printf("0x%x ", *(buf+i));
    // }
    // printf("\n");

    len = pkcs7_remove_padding(buf, len);

    // printf("\ndecrypted buffer without padding: ");

    // for(i = 0; i < len; i++){
    // 	printf("0x%x ", *(buf+i));
    // }
    // printf("\n");
    // printf("len = %d", len);

    // printf("\n");

    return len;

}



MQTTGWPacket* MQTTSNPublishHandler::handlePublish(Client* client, MQTTSNPacket* packet)
{
	uint8_t dup;
	int qos;
	uint8_t retained;
	uint16_t msgId;
	uint8_t* payload;
    MQTTSN_topicid topicid;
	int payloadlen;
	Publish pub = MQTTPacket_Publish_Initializer;

	char  shortTopic[2];

	if ( !_gateway->getAdapterManager()->getQoSm1Proxy()->isActive() )
	{
	    if ( client->isQoSm1() )
	    {
	        _gateway->getAdapterManager()->getQoSm1Proxy()->savePacket(client, packet);

	        return nullptr;
	    }
	}

	if ( packet->getPUBLISH(&dup, &qos, &retained, &msgId, &topicid, &payload, &payloadlen) ==0 )
	{
		return nullptr;
	}
	pub.msgId = msgId;
	pub.header.bits.dup = dup;
	pub.header.bits.qos = ( qos == 3 ? 0 : qos );
	pub.header.bits.retain = retained;

	Topic* topic = nullptr;

	if( topicid.type ==  MQTTSN_TOPIC_TYPE_SHORT )
	{
		shortTopic[0] = topicid.data.short_name[0];
		shortTopic[1] = topicid.data.short_name[1];
		pub.topic = shortTopic;
		pub.topiclen = 2;
	}
	else
	{
	    topic = client->getTopics()->getTopicById(&topicid);
	    if ( !topic )
	    {
	    	topic = _gateway->getTopics()->getTopicById(&topicid);
	    	if ( topic )
	    	{
	    		topic = client->getTopics()->add(topic->getTopicName()->c_str(), topic->getTopicId());
	    	}
	    }

	    if( !topic && qos == 3 )
	    {
	        WRITELOG("%s Invalid TopicId.%s %s\n", ERRMSG_HEADER, client->getClientId(), ERRMSG_FOOTER);
	        return nullptr;
	    }

	    if ( ( qos == 0 || qos == 3 ) && msgId > 0 )
	    {
	        WRITELOG("%s Invalid MsgId.%s %s\n", ERRMSG_HEADER, client->getClientId(), ERRMSG_FOOTER);
	        return nullptr;
	    }

		if( !topic && msgId && qos > 0 && qos < 3 )
		{
			/* Reply PubAck with INVALID_TOPIC_ID to the client */
			MQTTSNPacket* pubAck = new MQTTSNPacket();
			pubAck->setPUBACK( topicid.data.id, msgId, MQTTSN_RC_REJECTED_INVALID_TOPIC_ID);
			Event* ev1 = new Event();
			ev1->setClientSendEvent(client, pubAck);
			_gateway->getClientSendQue()->post(ev1);
			return nullptr;
		}
		if ( topic )
		{
			pub.topic = (char*)topic->getTopicName()->data();
			pub.topiclen = topic->getTopicName()->length();
		}
	}
	/* Save a msgId & a TopicId pare for PUBACK */
	if( msgId && qos > 0 && qos < 3)
	{
		client->setWaitedPubTopicId(msgId, topicid.data.id, topicid.type);
	}

	// 	printf("encrypted buffer:");

	// for(int i = 0; i < payloadlen; i++){
	// 	printf("0x%x ", *(payload+i));
	// }

// printf("\n");
	// decrypt the payload
	if(payloadlen>=16)
		payloadlen = decrypt_pkt_payload((uint8_t*)payload, payloadlen);

	// printf("\npayload = %s\n", payload);

	pub.payload = (char*)payload;
	pub.payloadlen = payloadlen;

	MQTTGWPacket* publish = new MQTTGWPacket();
	publish->setPUBLISH(&pub);

	if ( _gateway->getAdapterManager()->isAggregaterActive() && client->isAggregated() )
	{
		return publish;
	}
	else
	{
		Event* ev1 = new Event();
		ev1->setBrokerSendEvent(client, publish);
		_gateway->getBrokerSendQue()->post(ev1);
		return nullptr;
	}
}

void MQTTSNPublishHandler::handlePuback(Client* client, MQTTSNPacket* packet)
{
	uint16_t topicId;
	uint16_t msgId;
	uint8_t rc;

	if ( client->isActive() )
	{
		if ( packet->getPUBACK(&topicId, &msgId, &rc) == 0 )
		{
			return;
		}

		if ( rc == MQTTSN_RC_ACCEPTED)
		{
			if ( !_gateway->getAdapterManager()->getAggregater()->isActive() )
			{
				MQTTGWPacket* pubAck = new MQTTGWPacket();
				pubAck->setAck(PUBACK, msgId);
				Event* ev1 = new Event();
				ev1->setBrokerSendEvent(client, pubAck);
				_gateway->getBrokerSendQue()->post(ev1);
			}
		}
		else if ( rc == MQTTSN_RC_REJECTED_INVALID_TOPIC_ID)
		{
			WRITELOG("  PUBACK   %d : Invalid Topic ID\n", msgId);
		}
	}
}

void MQTTSNPublishHandler::handleAck(Client* client, MQTTSNPacket* packet, uint8_t packetType)
{
	uint16_t msgId;

	if ( client->isActive() )
	{
		if ( packet->getACK(&msgId) == 0 )
		{
			return;
		}
		MQTTGWPacket* ackPacket = new MQTTGWPacket();
		ackPacket->setAck(packetType, msgId);
		Event* ev1 = new Event();
		ev1->setBrokerSendEvent(client, ackPacket);
		_gateway->getBrokerSendQue()->post(ev1);
	}
}

void MQTTSNPublishHandler::handleRegister(Client* client, MQTTSNPacket* packet)
{
	uint16_t id;
	uint16_t msgId;
	MQTTSNString topicName  = MQTTSNString_initializer;;
	MQTTSN_topicid topicid;

	if ( client->isActive() || client->isAwake())
	{
		if ( packet->getREGISTER(&id, &msgId, &topicName) == 0 )
		{
			return;
		}

		topicid.type = MQTTSN_TOPIC_TYPE_NORMAL;
		topicid.data.long_.len = topicName.lenstring.len;
		topicid.data.long_.name = topicName.lenstring.data;

		id = client->getTopics()->add(&topicid)->getTopicId();

		MQTTSNPacket* regAck = new MQTTSNPacket();
		regAck->setREGACK(id, msgId, MQTTSN_RC_ACCEPTED);
		Event* ev = new Event();
		ev->setClientSendEvent(client, regAck);
		_gateway->getClientSendQue()->post(ev);
	}
}

void MQTTSNPublishHandler::handleRegAck( Client* client, MQTTSNPacket* packet)
{
    uint16_t id;
    uint16_t msgId;
    uint8_t rc;
    if ( client->isActive() || client->isAwake())
    {
        if ( packet->getREGACK(&id, &msgId, &rc) == 0 )
        {
            return;
        }

        MQTTSNPacket* regAck = client->getWaitREGACKPacketList()->getPacket(msgId);

        if ( regAck != nullptr )
        {
            client->getWaitREGACKPacketList()->erase(msgId);
            Event* ev = new Event();
            ev->setClientSendEvent(client, regAck);
            _gateway->getClientSendQue()->post(ev);
        }
        if (client->isHoldPringReqest() && client->getWaitREGACKPacketList()->getCount() == 0 )
        {
            /* send PINGREQ to the broker */
           client->resetPingRequest();
           MQTTGWPacket* pingreq = new MQTTGWPacket();
           pingreq->setHeader(PINGREQ);
           Event* evt = new Event();
           evt->setBrokerSendEvent(client, pingreq);
           _gateway->getBrokerSendQue()->post(evt);
        }
    }

}




void MQTTSNPublishHandler::handleAggregatePublish(Client* client, MQTTSNPacket* packet)
{
	int msgId = 0;
	MQTTGWPacket* publish = handlePublish(client, packet);
	if ( publish != nullptr )
	{
		if ( publish->getMsgId() > 0 )
		{
			if ( packet->isDuplicate() )
			{
				msgId = _gateway->getAdapterManager()->getAggregater()->getMsgId(client, packet->getMsgId());
			}
			else
			{
				msgId = _gateway->getAdapterManager()->getAggregater()->addMessageIdTable(client, packet->getMsgId());
			}
			publish->setMsgId(msgId);
		}
		Event* ev1 = new Event();
		ev1->setBrokerSendEvent(client, publish);
		_gateway->getBrokerSendQue()->post(ev1);
	}
}

void MQTTSNPublishHandler::handleAggregateAck(Client* client, MQTTSNPacket* packet, int type)
{
	if ( type == MQTTSN_PUBREC )
	{
		uint16_t msgId;

		if ( packet->getACK(&msgId) == 0 )
		{
			return;
		}
		MQTTSNPacket* ackPacket = new MQTTSNPacket();
		ackPacket->setPUBREL(msgId);
		Event* ev = new Event();
		ev->setClientSendEvent(client, ackPacket);
		_gateway->getClientSendQue()->post(ev);
	}
}
