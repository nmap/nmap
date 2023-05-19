
/***************************************************************************
 * PacketStats.cc -- The PacketStats class handles packet statistics. It   *
 * is intended to keep track of the number of packets and bytes sent and   *
 * received, keep track of start and finish times, etc.                    *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

#include "nping.h"
#include "stats.h"
#include "NpingOps.h"
#include "output.h"



/*****************************************************************************/
/* Implementation of NpingTimer class.                                       */
/*****************************************************************************/

NpingTimer::NpingTimer(){
  this->reset();
}

NpingTimer::~NpingTimer(){

}

void NpingTimer::reset(){
  this->start_tv.tv_sec=0;
  this->start_tv.tv_usec=0;
  this->stop_tv.tv_sec=0;
  this->stop_tv.tv_usec=0;
}


int NpingTimer::start(){
  if( timeval_set(&start_tv) || timeval_set(&stop_tv) )
    return OP_FAILURE;
  gettimeofday(&start_tv, NULL);
  return OP_SUCCESS;
}


int NpingTimer::stop(){
  if( !timeval_set(&start_tv) || timeval_set(&stop_tv) )
    return OP_FAILURE;
  gettimeofday(&stop_tv, NULL);
  return OP_SUCCESS;
}


double NpingTimer::elapsed(struct timeval *now){
  struct timeval tv;
  const struct timeval *end_tv=NULL;
  /* If for some reason the clock has not been started, 
   * just return 0 seconds elapsed. */
  if(!timeval_set(&start_tv)){
    return 0.0;
  }
  /* If the caller supplied a time, use it */
  if(now!=NULL){
    end_tv=now;
  /* If the clock has been stopped already, use the stop time */
  }else if(timeval_set(&stop_tv)){
    end_tv = &stop_tv;
  }else{
    gettimeofday(&tv, NULL);
    end_tv = &tv;
  }
  return TIMEVAL_FSEC_SUBTRACT(*end_tv, start_tv);
}


bool NpingTimer::is_started(){
  return timeval_set(&this->start_tv);
}


bool NpingTimer::is_stopped(){
  return timeval_set(&this->stop_tv);
}


/* Returns true if tv has been initialized; i.e., its members are not all zero. */
bool NpingTimer::timeval_set(const struct timeval *tv) {
  return (tv->tv_sec != 0 || tv->tv_usec != 0);
}



/*****************************************************************************/
/* Implementation of NpingStats class.                                       */
/*****************************************************************************/

NpingStats::NpingStats(){
  this->reset();
}


NpingStats::~NpingStats(){

}


void NpingStats::reset(){
  this->packets_sent=0;
  this->packets_received=0;
  this->packets_echoed=0;

  this->bytes_sent=0;
  this->bytes_received=0;
  this->bytes_echoed=0;

  this->echo_clients_served=0;

  this->tx_timer.reset();
  this->rx_timer.reset();
  this->run_timer.reset();

} /* End of reset() */


/** Updates packet and byte count for transmitted packets. */
int NpingStats::addSentPacket(u32 len){
  this->packets_sent++;
  this->bytes_sent+=len;
  return OP_SUCCESS;
} /* End of addSentPacket() */


/** Updates packet and byte count for received packets. */
int NpingStats::addRecvPacket(u32 len){
  this->packets_received++;
  this->bytes_received+=len;
  return OP_SUCCESS;
} /* End of addRecvPacket() */


/** Updates packet and byte count for echoed packets. */
int NpingStats::addEchoedPacket(u32 len){
  this->packets_echoed++;
  this->bytes_echoed+=len;
  return OP_SUCCESS;
} /* End of addEchoedPacket() */


/** Updates count for echo clients served by the echo server. */
int NpingStats::addEchoClientServed(){
  this->echo_clients_served++;
  return OP_SUCCESS;
} /* End of addEchoClientServed() */


int NpingStats::startClocks(){
  this->startTxClock();
  this->startRxClock();
  return OP_SUCCESS;
}


int NpingStats::stopClocks(){
  this->stopTxClock();
  this->stopRxClock();
  return OP_SUCCESS;
}


int NpingStats::startTxClock(){
  this->tx_timer.start();
  return OP_SUCCESS;
}


int NpingStats::stopTxClock(){
  this->tx_timer.stop();
  return OP_SUCCESS;
}

int NpingStats::startRxClock(){
  this->rx_timer.start();
  return OP_SUCCESS;
}


int NpingStats::stopRxClock(){
  this->rx_timer.stop();
  return OP_SUCCESS;
}


int NpingStats::startRuntime(){
  this->run_timer.start();
  return OP_SUCCESS;
}


int NpingStats::stopRuntime(){
  this->run_timer.start();
  return OP_SUCCESS;
}


double NpingStats::elapsedTx(){
  return this->tx_timer.elapsed();
}


double NpingStats::elapsedRx(){
  return this->rx_timer.elapsed();
}


double NpingStats::elapsedRuntime(struct timeval *now){
  return this->run_timer.elapsed(now);
}


u64_t NpingStats::getSentPackets(){
  return this->packets_sent;
} /* End of getSentPackets() */


u64_t NpingStats::getSentBytes(){
  return this->bytes_sent;
} /* End of getSentBytes() */


u64_t NpingStats::getRecvPackets(){
  return this->packets_received;
} /* End of getRecvPackets() */


u64_t NpingStats::getRecvBytes(){
  return this->bytes_received;
} /* End of getRecvBytes() */


u64_t NpingStats::getEchoedPackets(){
  return this->packets_echoed;
} /* End of getEchoedPackets() */


u64_t NpingStats::getEchoedBytes(){
  return this->bytes_echoed;
} /* End of getEchoedBytes() */

u32 NpingStats::getEchoClientsServed(){
  return this->echo_clients_served;
} /* End of getEchoClientsServed() */


u64_t NpingStats::getLostPackets(){
  if(this->packets_sent <= this->packets_received)
    return 0;
  else
    return this->packets_sent - this->packets_received;
} /* End of getLostPackets() */


double NpingStats::getLostPacketPercentage(){
  u32 pkt_rcvd=this->packets_received;
  u32 pkt_sent=this->packets_sent;
  u32 pkt_lost=(pkt_rcvd>=pkt_sent) ? 0 : (u32)(pkt_sent-pkt_rcvd);
  /* Only compute percentage if we actually sent packets, don't do divisions
   * by zero! (this could happen when user presses CTRL-C and we print the
   * stats */
  double percentlost=0.0;
  if( pkt_lost!=0 && pkt_sent!=0)
    percentlost=((double)pkt_lost)/((double)pkt_sent);
  return percentlost;
} /* End of getLostPacketPercentage() */


double NpingStats::getLostPacketPercentage100(){
  return this->getLostPacketPercentage()*100;
} /* End of getLostPacketPercentage100() */


u64_t NpingStats::getUnmatchedPackets(){
  if(this->packets_received <= this->packets_echoed)
    return 0;
  else
    return this->packets_received - this->packets_echoed;
} /* End of getUnmatchedPackets() */


double NpingStats::getUnmatchedPacketPercentage(){
  u32 pkt_captured=this->packets_received;
  u32 pkt_echoed=this->packets_echoed;
  u32 pkt_unmatched=(pkt_captured<=pkt_echoed) ? 0 : (u32)(pkt_captured-pkt_echoed);
  double percentunmatched=0.0;
  if( pkt_unmatched!=0 && pkt_captured!=0)
    percentunmatched=((double)pkt_unmatched)/((double)pkt_captured);
  return percentunmatched;
} /* End of getUnmatchedPacketPercentage() */


double NpingStats::getUnmatchedPacketPercentage100(){
  return this->getUnmatchedPacketPercentage()*100;
} /* End of getUnmatchedPacketPercentage100() */


double NpingStats::getOverallTxPacketRate(){
  double elapsed = this->tx_timer.elapsed();
  if(elapsed <= 0.0)
    return 0.0;
  else
    return this->packets_sent / elapsed;
}


double NpingStats::getOverallTxByteRate(){
  double elapsed = this->tx_timer.elapsed();
  if(elapsed <= 0.0)
    return 0.0;
  else
    return this->bytes_sent / elapsed;
}


double NpingStats::getOverallRxPacketRate(){
  double elapsed = this->rx_timer.elapsed();
  if(elapsed <= 0.0)
    return 0.0;
  else
    return this->packets_received / elapsed;
}


double NpingStats::getOverallRxByteRate(){
  double elapsed = this->rx_timer.elapsed();
  if(elapsed <= 0.0)
    return 0.0;
  else
    return this->bytes_received / elapsed;
}

