<?xml version="1.0"?>
<!-- =========================================================================
            nmap.xsl stylesheet version 0.9b
            last change: 2006-03-04
            Benjamin Erb, http://www.benjamin-erb.de
==============================================================================
    Copyright (c) 2004-2006 Benjamin Erb
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
    3. The name of the author may not be used to endorse or promote products
       derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
    IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
    NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
    THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
========================================================================== -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format">
<xsl:output method="html" indent="yes" encoding="UTF-8" />

<!-- global variables      -->
<!-- ............................................................ -->
<xsl:variable name="nmap_xsl_version">0.9b</xsl:variable>
<!-- ............................................................ -->
<xsl:variable name="start"><xsl:value-of select="/nmaprun/@startstr" /></xsl:variable>
<xsl:variable name="end"><xsl:value-of select="/nmaprun/runstats/finished/@timestr" /> </xsl:variable>
<xsl:variable name="totaltime"><xsl:value-of select="/nmaprun/runstats/finished/@time -/nmaprun/@start" /></xsl:variable>
<!-- ............................................................ -->


<xsl:template match="/">
	<xsl:apply-templates/>
</xsl:template>


<!-- root -->
<!-- ............................................................ -->
<xsl:template match="/nmaprun">
<html>
<head>

<xsl:comment>generated with nmap.xsl - version <xsl:value-of select="$nmap_xsl_version" /> by Benjamin Erb - http://www.benjamin-erb.de/nmap_xsl.php </xsl:comment>

<style type="text/css">
/* stylesheet print */
@media print
{
	#menu
	{
		display:none;
	}

	h1
	{
    	font-size: 13pt;
    	font-weight:bold;
    	margin:4pt 0pt 0pt 0pt;
    	padding:0;
	}

	h2
	{
    	font-size: 12pt;
    	font-weight:bold;
    	margin:3pt 0pt 0pt 0pt;
    	padding:0;
	}
	h3
	{
    	font-size: 9pt;
    	font-weight:bold;
    	margin:1pt 0pt 0pt 20pt;
    	padding:0;
	}

	p,ul
	{
    	font-size: 9pt;
    	margin:1pt 0pt 8pt 40pt;
    	padding:0;
    	text-align:left;

	}

	li
	{
    	font-size: 9pt;
    	margin:0;
    	padding:0;
    	text-align:left;

	}

	table
	{
    	margin:1pt 0pt 8pt 40pt;
    	border:0px;
    	width:90%
	}

	td
	{
    	border:0px;
    	border-top:1px solid black;
    	font-size: 9pt;
	}

	.head td
	{
		border:0px;
    	font-weight:bold;
    	font-size: 9pt;
	}


}

/* stylesheet screen */
@media screen
{
    body
    {
    	margin: 0px;
    	background-color: #FFFFFF;
    	color: #000000;
    	text-align: center;
    }

    #container
    {
        text-align:left;
        margin: 10px auto;
        width: 90%;
    }

    h1
    {
    	font-family: Verdana, Helvetica, sans-serif;
    	font-weight:bold;
    	font-size: 14pt;
    	color: #000000;
        background-color:#87CEFA;
        margin:10px 0px 0px 0px;
        padding:5px 4px 5px 4px;
        width: 100%;
        border:1px solid black;
        text-align: left;
    }

    h2
    {
        font-family: Verdana, Helvetica, sans-serif;
        font-weight:bold;
        font-size: 11pt;
        color: #000000;
        margin:30px 0px 0px 0px;
        padding:4px;
        width: 100%;
        border:1px solid black;
        background-color:#F0F8FF;
        text-align: left;
    }

    h2.green
    {
        color: #000000;
        background-color:#CCFFCC;
        border-color:#006400;
    }

    h2.red
    {
        color: #000000;
        background-color:#FFCCCC;
        border-color:#8B0000;
    }
   
    h3
    {
        font-family: Verdana, Helvetica, sans-serif;
        font-weight:bold;
        font-size: 10pt;
        color:#000000;
        background-color: #FFFFFF;
        width: 75%;
        text-align: left;
    }

    p
    {
        font-family: Verdana, Helvetica, sans-serif;
        font-size: 8pt;
        color:#000000;
        background-color: #FFFFFF;
        width: 75%;
        text-align: left;
    }

    p i
    {
        font-family: "Courier New", Courier, mono;
        font-size: 8pt;
        color:#000000;
        background-color: #CCCCCC;
    }

    ul
    {
        font-family: Verdana, Helvetica, sans-serif;
        font-size: 8pt;
        color:#000000;
        background-color: #FFFFFF;
        width: 75%;
        text-align: left;
    }

    a
    {
        font-family: Verdana, Helvetica, sans-serif;
        text-decoration: none;
        font-size: 8pt;
        color:#000000;
        font-weight:bold;
        background-color: #FFFFFF;
        color: #000000;
    }

    li a
    {
        font-family: Verdana, Helvetica, sans-serif;
        text-decoration: none;
        font-size: 10pt;
        color:#000000;
        font-weight:bold;
        background-color: #FFFFFF;
        color: #000000;
    }

    a:hover
    {
	    text-decoration: underline;
    }

    a.red
    {
        color:#8B0000;
    }
    a.green
    {
        color:#006400;
    }

    table
    {
        width: 80%;
        border:0px;
        color: #000000;
        background-color: #000000;
        margin:10px;
    }

    tr
    {
        vertical-align:top;
        font-family: Verdana, Helvetica, sans-serif;
        font-size: 8pt;
        color:#000000;
        background-color: #D1D1D1;
    }

    tr.head
    {
        background-color: #E1E1E1;
        color: #000000;
        font-weight:bold;
    }

    tr.open
    {
        background-color: #CCFFCC;
        color: #000000;
    }

    tr.filtered
    {
        background-color: #FFDDBB;
        color: #000000;
    }

    tr.closed
    {
        background-color: #FFAFAF;
        color: #000000;
    }
    
    td
    {
        padding:2px;
    }
    
    .status
    {
        display:none;
    }
    
    #menu li
    {
        display         : inline;
        margin          : 0;
        /*margin-right    : 10px;*/
        padding         : 0;
        list-style-type : none;
    }    
}
</style>
	<title>nmap report</title>
</head>

<body>
	<div id="container">
    <h1>nmap scan report - scan @ <xsl:value-of select="$start" />
    </h1>
    
    <ul id="menu">
    	<li><a href="#scansummary">scan summary</a><xsl:text> | </xsl:text></li>
    	<li><a href="#scaninfo">scan info</a><xsl:text> | </xsl:text></li>

          <xsl:for-each select="host">
              <xsl:sort select="substring ( address/@addr, 1, string-length ( substring-before ( address/@addr, '.' ) ) )* (256*256*256) + substring ( substring-after ( address/@addr, '.' ), 1, string-length ( substring-before ( substring-after ( address/@addr, '.' ), '.' ) ) )* (256*256) + substring ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), 1, string-length ( substring-before ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ) ) ) * 256 + substring ( substring-after ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ), 1 )" order="ascending" data-type="number"/>
              <li>
                <xsl:element name="a">
                    <xsl:attribute name="href">#<xsl:value-of select="translate(address/@addr, '.', '_') " /></xsl:attribute>
                    <xsl:attribute name="class">
                	<xsl:choose>
                        <xsl:when test="status/@state = 'up'">green</xsl:when>
                        <xsl:otherwise>red</xsl:otherwise>                    
                	</xsl:choose>
                    </xsl:attribute>
                    <xsl:value-of select="address/@addr"/>
                    <xsl:if test="count(hostnames/hostname) > 0">
                      <xsl:for-each select="hostnames/hostname">
                        <xsl:sort select="@name" order="ascending" data-type="text"/>
                        <xsl:text> / </xsl:text><xsl:value-of select="@name"/>
                      </xsl:for-each>                          
                    </xsl:if>                                
                </xsl:element>
               <xsl:text> | </xsl:text></li>
          </xsl:for-each>

        <li><a href="#runstats">runstats</a></li>
    </ul>
  
	<xsl:element name="a">
		<xsl:attribute name="name">scansummary</xsl:attribute>
	</xsl:element>
    <h2>scan summary</h2>
    <p>
	<xsl:value-of select="@scanner"/> was initiated at <xsl:value-of select="$start" /> with these arguments:<br/>
    <i><xsl:value-of select="@args" /></i><br/>
    The process stopped at <xsl:value-of select="$end" />.
	<xsl:choose>
        <xsl:when test="debugging/@level = '0'">Debugging was disabled, </xsl:when>
        <xsl:otherwise>Debugging was enabled, </xsl:otherwise>
    </xsl:choose>
    the verbosity level was <xsl:value-of select="verbose/@level" />.

    </p>
    <xsl:apply-templates select="host">
        <xsl:sort select="substring ( address/@addr, 1, string-length ( substring-before ( address/@addr, '.' ) ) )* (256*256*256) + substring ( substring-after ( address/@addr, '.' ), 1, string-length ( substring-before ( substring-after ( address/@addr, '.' ), '.' ) ) )* (256*256) + substring ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), 1, string-length ( substring-before ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ) ) ) * 256 + substring ( substring-after ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ), 1 )" order="ascending" data-type="number"/>
    </xsl:apply-templates>	
    <xsl:apply-templates select="runstats"/>
    </div>
    
</body>
</html>
</xsl:template>
<!-- ............................................................ -->

<!-- scaninfo -->
<!-- ............................................................ -->
<xsl:template match="scaninfo">
	<xsl:element name="a">
		<xsl:attribute name="name">scaninfo</xsl:attribute>
	</xsl:element>

	<h2>scan info</h2>
	<ul>
        <li><xsl:value-of select="@type" />-scan</li>
        <li><xsl:value-of select="@numservices" /><xsl:text> </xsl:text><xsl:value-of select="@protocol" /> services scanned</li>
	</ul>
	<xsl:apply-templates/>
</xsl:template>
<!-- ............................................................ -->

<!-- runstats -->
<!-- ............................................................ -->
<xsl:template match="runstats">
	<xsl:element name="a">
		<xsl:attribute name="name">runstats</xsl:attribute>
	</xsl:element>

	<h2>runstats</h2>
	<ul>
		<li><xsl:value-of select="$totaltime" /> sec. scanned</li>
        <li><xsl:value-of select="hosts/@total" /> host(s) scanned</li>
        <li><xsl:value-of select="hosts/@up" /> host(s) online</li>
        <li><xsl:value-of select="hosts/@down" /> host(s) offline</li>
	</ul>
	<ul>
		<li>nmap version: <xsl:value-of select="/nmaprun/@version" /></li>
        <li>xml output version: <xsl:value-of select="/nmaprun/@xmloutputversion" /></li>
        <li>nmap.xsl version: <xsl:value-of select="$nmap_xsl_version" /></li>
	</ul>
	<xsl:apply-templates/>
</xsl:template>
<!-- ............................................................ -->

<!-- host -->
<!-- ............................................................ -->
<xsl:template match="host">
	<xsl:element name="a">
		<xsl:attribute name="name"><xsl:value-of select="translate(address/@addr, '.', '_') " /></xsl:attribute>
	</xsl:element>

    <xsl:choose>
        <xsl:when test="status/@state = 'up'">
            <h2 class="green"><xsl:value-of select="address/@addr"/>
            <xsl:if test="count(hostnames/hostname) > 0">
              <xsl:for-each select="hostnames/hostname">
                <xsl:sort select="@name" order="ascending" data-type="text"/>
                <xsl:text> / </xsl:text><xsl:value-of select="@name"/>
              </xsl:for-each>                          
            </xsl:if>
            <span class="status">(online)</span>
            </h2>
        </xsl:when>
        <xsl:otherwise>
            <h2 class="red"><xsl:value-of select="address/@addr"/>
            <xsl:if test="count(hostnames/hostname) > 0">
              <xsl:for-each select="hostnames/hostname">
                <xsl:sort select="@name" order="ascending" data-type="text"/>
                <xsl:text> / </xsl:text><xsl:value-of select="@name"/>
              </xsl:for-each>            
            </xsl:if>             
            <span class="status">(offline)</span></h2>
        </xsl:otherwise>
    </xsl:choose>

	<h3>ping results</h3>
	<ul><li><xsl:value-of select="status/@reason"/>
    <xsl:if test="status/@reasonsrc">
    	<xsl:text> from </xsl:text>
    	<xsl:value-of select="status/@reasonsrc"/>
    </xsl:if></li></ul>

    <xsl:if test="count(address) > 0">    
        <h3>address</h3>
        <ul>
            <xsl:for-each select="address">
                <li><xsl:value-of select="@addr"/> (<xsl:value-of select="@addrtype"/>)</li>                
				
            </xsl:for-each>
        </ul>
    </xsl:if>
    
	<xsl:apply-templates/>

</xsl:template>
<!-- ............................................................ -->



<!-- hostnames -->
<!-- ............................................................ -->
<xsl:template match="hostnames">
<xsl:if test="hostname/@name != ''"><h3>hostnames</h3><ul>	<xsl:apply-templates/></ul></xsl:if>
</xsl:template>
<!-- ............................................................ -->

<!-- hostname -->
<!-- ............................................................ -->
<xsl:template match="hostname">
<li><xsl:value-of select="@name"/> (<xsl:value-of select="@type"/>)</li>
</xsl:template>
<!-- ............................................................ -->

<!-- ports -->
<!-- ............................................................ -->
<xsl:template match="ports">
<h3>ports</h3>
<xsl:for-each select="extraports">
    <xsl:if test="@count > 0">
	    <p>The <xsl:value-of select="@count" /> ports scanned but not shown below are in state: <b><xsl:value-of select="@state" /></b></p>
    </xsl:if>

    <ul>
    <xsl:for-each select="extrareasons">
        <xsl:if test="@count > 0">
            <li><p><xsl:value-of select="@count" /> ports replied with: <b><xsl:value-of select="@reason" /></b></p></li>
        </xsl:if>
    </xsl:for-each>
    </ul>
</xsl:for-each>

<xsl:if test="count(port) > 0">
    <table cellspacing="1">
    <tr class="head">
        <td colspan="2">Port</td>
        <td>State</td>
        <td>Service</td>
        <td>Reason</td>
        <td>Product</td>
        <td>Version</td>
        <td>Extra info</td>
    </tr>
	<xsl:apply-templates/>
	</table>
</xsl:if>	
</xsl:template>
<!-- ............................................................ -->

<!-- port -->
<!-- ............................................................ -->
<xsl:template match="port">
	<xsl:choose>
		<xsl:when test="state/@state = 'open'">
            <tr class="open">
                <td><xsl:value-of select="@portid" /></td>
                <td><xsl:value-of select="@protocol" /></td>
                <td><xsl:value-of select="state/@state" /></td>
                <td><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></td>
				<td><xsl:value-of select="state/@reason"/>
 				    <xsl:if test="state/@reason_ip">
                      <xsl:text> from </xsl:text>
                      <xsl:value-of select="state/@reason_ip"/>
                   </xsl:if>
				</td>
                <td><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></td>
                <td><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></td>
                <td><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></td>
            </tr>
	    <xsl:for-each select="script">
		    <tr class="open">
			    <td></td>
			    <td>
				    <xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text>
			    </td>
			    <td colspan="5">
				    <xsl:value-of select="@output"/> <xsl:text>&#xA0;</xsl:text>
			    </td>
			    </tr>

		    </xsl:for-each>

		</xsl:when>
		<xsl:when test="state/@state = 'filtered'">
            <tr class="filtered">
                <td><xsl:value-of select="@portid" /></td>
                <td><xsl:value-of select="@protocol" /></td>
                <td><xsl:value-of select="state/@state" /></td>
                <td><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></td>
				<td><xsl:value-of select="state/@reason"/>
 				    <xsl:if test="state/@reason_ip">
                      <xsl:text> from </xsl:text>
                      <xsl:value-of select="state/@reason_ip"/>
                   </xsl:if>
				</td>
                <td><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></td>
                <td><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></td>
                <td><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></td>
            </tr>
		</xsl:when>
		<xsl:when test="state/@state = 'closed'">
            <tr class="closed">
                <td><xsl:value-of select="@portid" /></td>
                <td><xsl:value-of select="@protocol" /></td>
                <td><xsl:value-of select="state/@state" /></td>
                <td><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></td>
				<td><xsl:value-of select="state/@reason"/>
 				    <xsl:if test="state/@reason_ip">
                      <xsl:text> from </xsl:text>
                      <xsl:value-of select="state/@reason_ip"/>
                   </xsl:if>
				</td>
                <td><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></td>
                <td><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></td>
                <td><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></td>
            </tr>
		</xsl:when>
		<xsl:otherwise>
            <tr>
                <td><xsl:value-of select="@portid" /></td>
                <td><xsl:value-of select="@protocol" /></td>
                <td><xsl:value-of select="state/@state" /></td>
                <td><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></td>
                <td><xsl:value-of select="state/@reason"/>
 				    <xsl:if test="state/@reason_ip">
                      <xsl:text> from </xsl:text>
                      <xsl:value-of select="state/@reason_ip"/>
                   </xsl:if>
				</td>
                <td><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></td>
                <td><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></td>
                <td><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></td>
            </tr>
		</xsl:otherwise>
	</xsl:choose>
</xsl:template>
<!-- ............................................................ -->

<!-- os -->
<!-- ............................................................ -->
<xsl:template match="os">
	<h3>remote operating system guess</h3>
		
	<xsl:if test="count(osmatch) = 0"><p>Unable to identify operating system.</p></xsl:if>	

	<ul>
		<xsl:apply-templates/>
	</ul>
</xsl:template>
<!-- ............................................................ -->

<!-- os portused -->
<!-- ............................................................ -->
<xsl:template match="portused">
<li>used port <xsl:value-of select="@portid" />/<xsl:value-of select="@proto" /> (<xsl:value-of select="@state" />)  </li>
</xsl:template>
<!-- ............................................................ -->

<!-- os match -->
<!-- ............................................................ -->
<xsl:template match="osmatch">
<li>os match: <b><xsl:value-of select="@name" /> </b></li>
<li>accuracy: <xsl:value-of select="@accuracy" />%</li>
<li>reference fingerprint line number: <xsl:value-of select="@line" /></li>
</xsl:template>
<!-- ............................................................ -->

<!-- osfingerprint -->
<!-- ............................................................ -->
<xsl:template match="osfingerprint">
       <xsl:choose>
               <xsl:when test="count(../osmatch)=0">
                       <br /><br />
                       <li>Cannot determine exact operating system.  Fingerprint provided below.</li>
                       <li>If you know what OS is running on it, see http://nmap.org/submit/</li>
               </xsl:when>
               <xsl:otherwise>
                       <br /><br />
                       <li>OS Fingerprint requested at scan time and provided below.</li>
               </xsl:otherwise>
       </xsl:choose>


	<table cellspacing="1">
		<tr class="head">
    		<td>Operating System fingerprint</td>
		</tr>
		<tr>
                       <td><pre><xsl:value-of select="@fingerprint" /></pre></td>
		</tr>
	</table>

</xsl:template>
<!-- ............................................................ -->

<!-- Host Script Scan -->
<!-- ............................................................ -->
<xsl:template match="hostscript">
	<table>
	<xsl:for-each select="script">
		<tr class="open">
			<td>
				<xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text>
			</td>
			<td>
				<xsl:value-of select="@output"/> <xsl:text>&#xA0;</xsl:text>
			</td>
		</tr>

	</xsl:for-each>
	</table>
</xsl:template>
<!-- ............................................................ -->

<!-- uptime -->
<!-- ............................................................ -->
<xsl:template match="uptime">
<xsl:if test="@seconds != ''"><h3>system uptime</h3>
<ul>
<li>uptime: <xsl:value-of select="@seconds" /> sec</li>
<li>last reboot: <xsl:value-of select="@lastboot" /></li>
</ul>
</xsl:if>
</xsl:template>
<!-- ............................................................ -->

<!-- distance -->
<!-- ............................................................ -->
<xsl:template match="distance">
<xsl:if test="@value != ''"><h3>network distance</h3>
<ul>
	<li>distance: <xsl:value-of select="@value" /> hops</li>
</ul>
</xsl:if>
</xsl:template>
<!-- ............................................................ -->

<!-- smurf -->
<!-- ............................................................ -->
<xsl:template match="smurf">
<xsl:if test="@responses != ''"><h3>smurf responses</h3>
<ul>
<li><xsl:value-of select="@responses" /> responses counted</li>
</ul>
</xsl:if>
</xsl:template>
<!-- ............................................................ -->

<!-- tcpsequence -->
<!-- ............................................................ -->
<xsl:template match="tcpsequence">
<xsl:if test="@values != ''">
    <h3>tcpsequence</h3>
    <ul>
        <li>index: <xsl:value-of select="@index" /></li>
        <li>difficulty: <xsl:value-of select="@difficulty" /></li>
        <li>values: <xsl:value-of select="@values" /></li>
    </ul>
</xsl:if>
</xsl:template>
<!-- ............................................................ -->

<!-- traceroute -->
<!-- ............................................................ -->

<xsl:template match="trace">
  <h3>traceroute</h3>
  <ul>
      <xsl:choose>
        <xsl:when test="@port">
          <li>port: <xsl:value-of select="@port" /></li>
        </xsl:when>
      </xsl:choose>
      <li>proto: <xsl:value-of select="@proto" /></li>
       <xsl:for-each select="error">
        <li>error: <xsl:value-of select="@errorstr"/></li>
       </xsl:for-each>
  </ul>
  <table cellspacing="1">
    <tr class="head">
      <td>Hop</td>
      <td>Rtt</td>
      <td>IP</td>
      <td>Host</td>
    </tr>
  <xsl:for-each select="hop">
      <xsl:choose>
          <xsl:when test="@rtt = '--'">
      <tr class="filtered">
          <td><xsl:value-of select="@ttl" /></td>
          <td>--</td>
          <td><xsl:value-of select="@ipaddr" /></td>
          <td><xsl:value-of select="@host" /></td>
        </tr>
      </xsl:when>
          <xsl:when test="@rtt > 0">
        <tr class="open">
          <td><xsl:value-of select="@ttl" /></td>
          <td><xsl:value-of select="@rtt" /></td>
          <td><xsl:value-of select="@ipaddr" /></td>
          <td><xsl:value-of select="@host" /></td>
        </tr>
      </xsl:when>
      <xsl:otherwise>
        <tr class="closed">
          <td><xsl:value-of select="@ttl" /></td>
          <td></td><td></td><td></td>
        </tr>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:for-each>
  </table>
</xsl:template>
<!-- ............................................................ -->



<!-- ipidsequence -->
<!-- ............................................................ -->
<xsl:template match="ipidsequence">
<xsl:if test="@values != ''">
    <h3>ipidsequence</h3>
    <ul>
        <li>class: <xsl:value-of select="@class" /></li>
        <li>values: <xsl:value-of select="@values" /></li>
    </ul>
</xsl:if>
</xsl:template>
<!-- ............................................................ -->

<!-- tcptssequence -->
<!-- ............................................................ -->
<xsl:template match="tcptssequence">
<xsl:if test="@values != ''">
    <h3>tcptssequence</h3>
    <ul>
        <li>class: <xsl:value-of select="@class" /></li>
        <li>values: <xsl:value-of select="@values" /></li>
    </ul>
</xsl:if>
</xsl:template>
<!-- ............................................................ -->

</xsl:stylesheet>
