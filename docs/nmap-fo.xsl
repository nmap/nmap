<?xml version="1.0" encoding="UTF-8"?>
<!-- =========================================================================
		nmap_fo.xls stylesheet version 1.010
		https://github.com/tilikammon/nmap-to-fo
		last change: 2013-01-20
		Gustave Walzer

		Usage
		==============

		* Run nmap with -oX flag for xml output:
		      $  nmap -oX ./nmap.scan.xml localhost


		* Convert output xml to pdf using the above xsl file with fop:
		       $ fop -xml nmap.scan.xml -xsl nmap_fo.xsl -pdf nmap.scan.pdf

========================================================================== -->

<!-- =========================================================================
            nmap.xsl stylesheet version 0.9c
            last change: 2010-12-28
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


<xsl:stylesheet version="1.0" 
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
	xmlns:fo="http://www.w3.org/1999/XSL/Format">

<!-- Base Document -->
<xsl:template match="/">
	<fo:root>
		<fo:layout-master-set>
			<fo:simple-page-master master-name="simple" page-height="29.7cm" page-width="21cm" margin-top="1cm" margin-bottom="2cm" margin-left="2.5cm" margin-right="2.5cm">
				<fo:region-body margin-top="3cm"/>
				<fo:region-before extent="3cm"/>
				<fo:region-after extent="1.5cm"/>
			</fo:simple-page-master>
		</fo:layout-master-set>

		<fo:bookmark-tree>
			<fo:bookmark internal-destination="summary">
				<fo:bookmark-title>Summary</fo:bookmark-title>
			</fo:bookmark>
			
			<xsl:if test="/nmaprun/prescript">
				<fo:bookmark internal-destination="prescript">
					<fo:bookmark-title>Pre-Scan Script Output</fo:bookmark-title>
				</fo:bookmark>
			</xsl:if>

			<xsl:for-each select="nmaprun/host">

				<xsl:sort select="substring ( address/@addr, 1, string-length ( substring-before ( address/@addr, '.' ) ) )* (256*256*256) + substring ( substring-after ( address/@addr, '.' ), 1, string-length ( substring-before ( substring-after ( address/@addr, '.' ), '.' ) ) )* (256*256) + substring ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), 1, string-length ( substring-before ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ) ) ) * 256 + substring ( substring-after ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ), 1 )" order="ascending" data-type="number"/>

				<fo:bookmark internal-destination="host.{generate-id()}">
					<fo:bookmark-title>
						<xsl:if test="count(hostnames/hostname) > 0">
							<xsl:value-of select="hostnames/hostname/@name"/> (<xsl:value-of select="address/@addr"/>)
						</xsl:if>
					
						<xsl:if test="count(hostnames/hostname) = 0">
							<xsl:value-of select="address/@addr"/>
						</xsl:if>
					</fo:bookmark-title>
						
						<xsl:if test="address">
							<fo:bookmark internal-destination="address.{generate-id()}">
								<fo:bookmark-title>Address</fo:bookmark-title>
							</fo:bookmark>
						</xsl:if>
						
						<xsl:if test="count(hostnames/hostname) > 0">
							<fo:bookmark internal-destination="hostname.{generate-id(hostnames)}">
								<fo:bookmark-title>Hostname</fo:bookmark-title>
							</fo:bookmark>
						</xsl:if>
						
						<xsl:if test="ports">
							<fo:bookmark internal-destination="port.{generate-id(ports)}">
								<fo:bookmark-title>Ports</fo:bookmark-title>
							</fo:bookmark>
						</xsl:if>
						
						<xsl:if test="hostscript">
							<fo:bookmark internal-destination="hostscript.{generate-id(hostscript)}">
								<fo:bookmark-title>Host Script Output</fo:bookmark-title>
							</fo:bookmark>
						</xsl:if>
						
						<xsl:if test="trace">
							<fo:bookmark internal-destination="traceroute.{generate-id(trace)}" >
								<fo:bookmark-title>Traceroute</fo:bookmark-title>
							</fo:bookmark>
						</xsl:if>
				</fo:bookmark>
			</xsl:for-each>
			
			<xsl:if test="/nmaprun/postscript">
				<fo:bookmark internal-destination="postscript">
					<fo:bookmark-title>Post-Scan Script Output</fo:bookmark-title>
				</fo:bookmark>
			</xsl:if>

		</fo:bookmark-tree>

		<fo:page-sequence master-reference="simple">
			<fo:flow flow-name="xsl-region-body">
				<xsl:apply-templates select="nmaprun"/>
			</fo:flow>
		</fo:page-sequence>
	</fo:root>
</xsl:template>
<!-- ............................................................ -->

<!-- nmaprun -->
<xsl:template match="nmaprun">
	<fo:block font-size="14pt" font-family="sans-serif" background-color="#2A0D45" color="#FFFFFF" padding-top="3pt" id="head">
	Nmap Scan Report - Scanned at <xsl:value-of select="@startstr"/>
	</fo:block>

	<fo:block font-size="8pt" font-family="sans-serif" padding-top="10pt" start-indent="20pt" text-align="left" color="#000000" >
	<fo:basic-link internal-destination="summary"><fo:inline font-weight="bold">Scan Summary</fo:inline></fo:basic-link>

	<xsl:if test="prescript/script/@id">
		<xsl:text> | </xsl:text>
		<fo:basic-link internal-destination="prescript"><fo:inline font-weight="bold">Pre-Scan Script Output</fo:inline></fo:basic-link>
	</xsl:if>

	<xsl:for-each select="host">
		<xsl:sort select="substring ( address/@addr, 1, string-length ( substring-before ( address/@addr, '.' ) ) )* (256*256*256) + substring ( substring-after ( address/@addr, '.' ), 1, string-length ( substring-before ( substring-after ( address/@addr, '.' ), '.' ) ) )* (256*256) + substring ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), 1, string-length ( substring-before ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ) ) ) * 256 + substring ( substring-after ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ), 1 )" order="ascending" data-type="number"/>

	<xsl:text> | </xsl:text>

	<xsl:variable name="var_address" select="address/@addr" />
	
	<fo:inline font-size="8pt" font-family="sans-serif" font-weight="bold" padding-top="3pt" padding-bottom="3pt" text-align="left" background-color="#CCFFCC" color="#006400">
	<xsl:if test="count(hostnames/hostname) > 0">
		<xsl:for-each select="hostnames">
			<fo:basic-link internal-destination="host.{generate-id(..)}"><xsl:value-of select="hostname/@name"/> (<xsl:value-of select="$var_address"/>)</fo:basic-link>
		</xsl:for-each>
	</xsl:if>

	<xsl:if test="count(hostnames/hostname) = 0">
		<fo:basic-link internal-destination="host.{generate-id()}"><xsl:value-of select="address/@addr"/></fo:basic-link>
	</xsl:if>
	</fo:inline>
	
	</xsl:for-each>

	<xsl:if test="postscript/script/@id">
	<xsl:text> | </xsl:text>
	<fo:basic-link internal-destination="postscript"><fo:inline font-weight="bold">Post-Scan Script Output</fo:inline></fo:basic-link>
	</xsl:if>
	</fo:block>
	
	<fo:block>&#160;</fo:block>
	
	<fo:block font-size="11pt" font-family="sans-serif" font-weight="bold" padding-top="3pt" text-align="left" background-color="#F0F8FF" color="#000000" id="summary">
	Scan Summary
	</fo:block>
	
	<fo:block font-size="8pt" font-family="sans-serif" padding-top="6pt" color="#000000">
	Nmap <xsl:value-of select="@version" /> was initiated at <xsl:value-of select="/nmaprun/@startstr" /> with these arguments:
	</fo:block>
	
	<fo:block font-size="8pt" font-family="sans-serif" font-style="italic" background-color="#CCCCCC" color="#000000">
	<xsl:value-of select="@args" />
	</fo:block>

	<fo:block>&#160;</fo:block>

	<fo:block font-size="8pt" font-family="sans-serif" color="#000000">
	Verbosity: <xsl:value-of select="verbose/@level" />; Debug level <xsl:value-of select="debugging/@level"/>
	</fo:block>

	<fo:block>&#160;</fo:block>

	<fo:block font-size="8pt" font-family="sans-serif" color="#000000">
	<xsl:value-of select="/nmaprun/runstats/finished/@summary" />
	</fo:block>

	<fo:block font-size="6pt" font-family="sans-serif" padding-top="10pt">
	<fo:basic-link internal-destination="head">back to top</fo:basic-link>
	</fo:block>

	<fo:block>&#160;</fo:block>

	<xsl:apply-templates select="prescript"/>

	<xsl:apply-templates select="host">
		<xsl:sort select="substring ( address/@addr, 1, string-length ( substring-before ( address/@addr, '.' ) ) )* (256*256*256) + substring ( substring-after ( address/@addr, '.' ), 1, string-length ( substring-before ( substring-after ( address/@addr, '.' ), '.' ) ) )* (256*256) + substring ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), 1, string-length ( substring-before ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ) ) ) * 256 + substring ( substring-after ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ), 1 )" order="ascending" data-type="number"/>
	</xsl:apply-templates>

	<xsl:apply-templates select="postscript"/>

</xsl:template>
<!-- ............................................................ -->

<!-- Hosts -->
<xsl:template match="host">

<xsl:choose>

	<xsl:when test="status/@state = 'up'">
	<fo:block font-size="11pt" font-family="sans-serif" font-weight="bold" background-color="#CCFFCC" padding-top="3pt" padding-left="3pt" color="#000000" id="host.{generate-id()}">
	<xsl:value-of select="address/@addr"/>
	<xsl:if test="count(hostnames/hostname) > 0">
		<xsl:for-each select="hostnames/hostname">
			<xsl:sort select="@name" order="ascending" data-type="text"/>
			<xsl:text> / </xsl:text><xsl:value-of select="@name"/>
		</xsl:for-each>
	</xsl:if>
	</fo:block>
	</xsl:when>

	<xsl:otherwise>
	<fo:block font-size="11pt" font-family="sans-serif" font-weight="bold" background-color="#E1E1E1" padding-top="3pt" padding-left="3pt" id="host.{generate-id()}">
	<xsl:value-of select="address/@addr"/>
	<xsl:if test="count(hostnames/hostname) > 0">
	<xsl:for-each select="hostnames/hostname">
		<xsl:sort select="@name" order="ascending" data-type="text"/>
			<xsl:text> / </xsl:text><xsl:value-of select="@name"/>
	</xsl:for-each>
	</xsl:if>
	(<xsl:value-of select="status/@state"/>)
	</fo:block>
	</xsl:otherwise>
</xsl:choose>

<fo:block font-size="10pt" font-family="sans-serif" font-weight="bold" padding-top="10pt" padding-bottom="5pt" color="#000000" id="address.{generate-id()}">
Address
</fo:block>

<fo:block font-size="8pt" font-family="sans-serif" start-indent="15pt" color="#000000">
<xsl:if test="count(address) > 0">
	<xsl:for-each select="address">
		&#8226; <xsl:value-of select="@addr"/>
		<xsl:if test="@vendor">
			<xsl:text> - </xsl:text>
			<xsl:value-of select="@vendor"/>
			<xsl:text> </xsl:text>
		</xsl:if>
		(<xsl:value-of select="@addrtype"/>)
	</xsl:for-each>
</xsl:if>
</fo:block>

<fo:block font-size="2pt"></fo:block>

<xsl:apply-templates/>

<fo:block font-family="sans-serif" font-size="10pt" font-weight="bold" padding-top="10pt" padding-bottom="5pt">
Misc Metrics
</fo:block>

<fo:table>
	<fo:table-header>
		<fo:table-cell border="solid black 1px">
			<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold" background-color="#E1E1E1">Metric</fo:block>
		</fo:table-cell>
		<fo:table-cell border="solid black 1px">
			<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold" background-color="#E1E1E1">Value</fo:block>
		</fo:table-cell>
	</fo:table-header>

	<fo:table-body>
		<fo:table-row>
			<fo:table-cell border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt">Ping Results</fo:block>
			</fo:table-cell>
			<fo:table-cell border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt">
				<xsl:value-of select="status/@reason"/>
				<xsl:if test="status/@reasonsrc">
					<xsl:text> from </xsl:text>
					<xsl:value-of select="status/@reasonsrc"/>
				</xsl:if>
				</fo:block>
			</fo:table-cell>
		</fo:table-row>

		<xsl:if test="uptime/@seconds != ''">
			<fo:table-row>
				<fo:table-cell border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">System Uptime</fo:block>
				</fo:table-cell>
				<fo:table-cell border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">
					<xsl:value-of select="uptime/@seconds" /> seconds  (last reboot: <xsl:value-of select="uptime/@lastboot" />)
					</fo:block>
				</fo:table-cell>
			</fo:table-row>
		</xsl:if>

		<xsl:if test="distance/@value != ''">
			<fo:table-row>
				<fo:table-cell border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">Network Distance</fo:block>
				</fo:table-cell>
				<fo:table-cell border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">
					<xsl:value-of select="distance/@value" /> hops
					</fo:block>
				</fo:table-cell>
			</fo:table-row>
		</xsl:if>


		<xsl:if test="tcpsequence/@index != ''">
			<fo:table-row>
				<fo:table-cell border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">TCP Sequence Prediction</fo:block>
				</fo:table-cell>
				<fo:table-cell border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">
					Difficulty=<xsl:value-of select="tcpsequence/@index" /> (<xsl:value-of select="tcpsequence/@difficulty" />)
					</fo:block>
				</fo:table-cell>
			</fo:table-row>
		</xsl:if>

		<xsl:if test="ipidsequence/@class != ''">
			<fo:table-row>
			<fo:table-cell border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt">IP ID Sequence Geneation</fo:block>
			</fo:table-cell>
			<fo:table-cell border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt">
				<xsl:value-of select="ipidsequence/@class" />
				</fo:block>
			</fo:table-cell>
			</fo:table-row>
		</xsl:if>

	</fo:table-body>
</fo:table>

<fo:block>&#160;</fo:block>

<fo:block font-size="6pt" font-family="sans-serif">
<fo:basic-link internal-destination="head">Back to top</fo:basic-link>
</fo:block>

<fo:block>&#160;</fo:block>

</xsl:template>
<!-- ............................................................ -->

<!-- hostnames -->
<xsl:template match="hostnames">
<xsl:if test="hostname/@name != ''">
	<fo:block font-size="10pt" font-family="sans-serif" font-weight="bold" padding-top="10pt" padding-bottom="5pt" color="#000000" id="hostname.{generate-id()}">
	Hostnames
	</fo:block>
	<xsl:apply-templates/>
</xsl:if>

</xsl:template>
<!-- ............................................................ -->

<!-- hostname -->
<xsl:template match="hostname">
<fo:block font-size="8pt" font-family="sans-serif" start-indent="15pt" color="#000000">
&#8226; <xsl:value-of select="@name"/> (<xsl:value-of select="@type"/>)
</fo:block>
</xsl:template>
<!-- ............................................................ -->

<!-- Ports -->
<xsl:template match="ports">
<xsl:variable name="var_address" select="../address/@addr" />

<fo:block font-size="10pt" font-family="sans-serif" font-weight="bold" padding-top="10pt" padding-bottom="5pt" color="#000000" id="port.{generate-id()}">
Ports
</fo:block>

<xsl:for-each select="extraports">
	<xsl:if test="@count > 0">
	<fo:block font-size="8pt" font-family="sans-serif" padding-bottom="5pt" color="#000000">
	The <xsl:value-of select="@count"/> ports scanned but not shown below are in state: <fo:inline font-weight="bold"> <xsl:value-of select="@state"/> </fo:inline> 
	</fo:block>
	</xsl:if>

	<xsl:for-each select="extrareasons">
		<xsl:if test="@count > 0">
			<fo:block font-size="8pt" font-family="sans-serif" start-indent="15pt" color="#000000">
			&#8226; <xsl:value-of select="@count"/> ports replied with: <fo:inline font-weight="bold"> <xsl:value-of select="@reason"/> </fo:inline>
			</fo:block>
		</xsl:if>
	</xsl:for-each>
</xsl:for-each>

<fo:block font-size="8pt" font-family="sans-serif">&#160;</fo:block>

<xsl:if test="count(port) > 0">
	<fo:table>
	<fo:table-header>
		<fo:table-row>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px" number-columns-spanned="2">
				<fo:block font-size="8pt" font-family="sans-serif" background-color="#E1E1E1" font-weight="bold">Port</fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif" background-color="#E1E1E1" font-weight="bold">State</fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif" background-color="#E1E1E1" font-weight="bold">Service</fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif" background-color="#E1E1E1" font-weight="bold">Reason</fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif" background-color="#E1E1E1" font-weight="bold">Product</fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif" background-color="#E1E1E1" font-weight="bold">Version</fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif" background-color="#E1E1E1" font-weight="bold">Extra Info</fo:block>
			</fo:table-cell>
		</fo:table-row>
	</fo:table-header>
	
	<fo:table-body>
	<xsl:apply-templates/>
	</fo:table-body>

	</fo:table>
</xsl:if>

</xsl:template>
<!-- ............................................................ -->

<!-- port -->
<xsl:template match="port">

<xsl:choose>
	<xsl:when test="state/@state = 'open'">
		<fo:table-row>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px" width="35pt">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@portid" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px" width="25pt">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@protocol" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@state" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@reason"/></fo:block>
		</fo:table-cell>
		<xsl:if test="state/@reason_ip">
			<xsl:text> from </xsl:text>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@reason_ip"/></fo:block>
			</fo:table-cell>
		</xsl:if>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
		<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></fo:block>
			</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		</fo:table-row>
		<xsl:for-each select="script">
			<fo:table-row>
			<fo:table-cell background-color="#EFFFF7" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text></fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#EFFFF7" border="solid black 1px" number-columns-spanned="7">
				<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@output"/> <xsl:text>&#xA0;</xsl:text></fo:block>
			</fo:table-cell>
			</fo:table-row>
		</xsl:for-each>
	</xsl:when>
	
	<xsl:when test="state/@state = 'filtered'">
		<fo:table-row>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@portid" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@protocol" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@state" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@reason"/></fo:block>
		</fo:table-cell>
		<xsl:if test="state/@reason_ip">
			<xsl:text> from </xsl:text>
			<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@reason_ip"/></fo:block>
			</fo:table-cell>
		</xsl:if>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
			<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
		<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		</fo:table-row>
	</xsl:when>
	
	<xsl:when test="state/@state = 'closed'">
		<fo:table-row>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@portid" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@protocol" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@state" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@reason"/></fo:block>
		</fo:table-cell>
		<xsl:if test="state/@reason_ip">
			<xsl:text> from </xsl:text>
			<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@reason_ip"/></fo:block>
			</fo:table-cell>
		</xsl:if>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		</fo:table-row>
	</xsl:when>
	
	<xsl:otherwise>
		<fo:table-row>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@portid" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="@protocol" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@state" /></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@reason"/></fo:block>
		</fo:table-cell>
		<xsl:if test="state/@reason_ip">
			<xsl:text> from </xsl:text>
			<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
				<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="state/@reason_ip"/></fo:block>
			</fo:table-cell>
		</xsl:if>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
			<fo:block font-size="8pt" font-family="sans-serif"><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></fo:block>
		</fo:table-cell>
		</fo:table-row>
	</xsl:otherwise>
</xsl:choose>

</xsl:template>
<!-- ............................................................ -->

<!-- os -->
<xsl:template match="os">
<fo:block font-size="10pt" font-family="sans-serif" font-weight="bold" padding-top="15pt" padding-bottom="5pt" color="#000000" id="remote.{generate-id()}">
Remote Operating System Detection
</fo:block>

<xsl:if test="count(osmatch) = 0">
	<fo:block font-size="8pt" font-family="sans-serif" color="#000000">
	Unable to identify operating system.
	</fo:block>
</xsl:if>

<xsl:for-each select="portused">
	<fo:block font-size="8pt" font-family="sans-serif" start-indent="15pt" color="#000000">
	&#8226; Used port: <fo:inline font-weight="bold"> <xsl:value-of select="@portid" />/<xsl:value-of select="@proto"/> (<xsl:value-of select="@state"/>) </fo:inline>
	</fo:block>
</xsl:for-each>

<xsl:for-each select="osmatch">
	<fo:block font-size="8pt" font-family="sans-serif" start-indent="15pt" color="#000000">
	&#8226; OS match: <fo:inline font-weight="bold"> <xsl:value-of select="@name"/> (<xsl:value-of select="@accuracy"/>%) </fo:inline>
	</fo:block>
</xsl:for-each>


<xsl:apply-templates select="osfingerprint"/>

</xsl:template>
<!-- ............................................................ -->

<!-- osfingerprint -->
<xsl:template match="osfingerprint">

<fo:block>&#160;</fo:block>

<xsl:choose>
	<xsl:when test="count(../osmatch)=0">
	<fo:block font-family="sans-serif" font-size="10pt" font-weight="bold">
	Cannot determine exact operating system.  Fingerprint provided below.
	If you know what OS is running on it, see https://nmap.org/submit/
	</fo:block>

	<fo:table>
		<fo:table-header>
			<fo:table-row>
				<fo:table-cell border="solid black 1px" background-color="#E1E1E1">
					<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">
					Operating System fingerprint
					</fo:block>
				</fo:table-cell>
			</fo:table-row>
		</fo:table-header>

		<fo:table-body>
			<fo:table-row>
				<fo:table-cell border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">
					<xsl:value-of select="@fingerprint"/>
					</fo:block>
				</fo:table-cell>
			</fo:table-row>
		</fo:table-body>
	</fo:table>
	</xsl:when>

	<xsl:otherwise>
	<fo:table>
		<fo:table-header>
			<fo:table-cell border="solid black 1px" background-color="#E1E1E1">
				<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">
				Operating System fingerprint
				</fo:block>
			</fo:table-cell>
		</fo:table-header>

		<fo:table-body>
			<fo:table-row>
				<fo:table-cell border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">
					<xsl:value-of select="@fingerprint"/>
					</fo:block>
			</fo:table-cell>
			</fo:table-row>
		</fo:table-body>
	</fo:table>
	</xsl:otherwise>

</xsl:choose>

</xsl:template>
<!-- ............................................................ -->

<!-- Pre-Scan script -->
<xsl:template match="prescript">
<fo:block font-family="sans-serif" font-size="11pt" font-weight="bold" padding-top="3" background-color="#F0F8FF" id="prescript">
Pre-Scan Script Output
</fo:block>

<fo:block>&#160;</fo:block>

<fo:table start-indent="10pt">
	<fo:table-header>
		<fo:table-row>
			<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">Script Name</fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">Output</fo:block>
			</fo:table-cell>
		</fo:table-row>
	</fo:table-header>

	<fo:table-body>
		<xsl:for-each select="script">
			<fo:table-row>
				<fo:table-cell background-color="#EFFFF7" border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">
					<xsl:value-of select="@id"/>
					</fo:block>
				</fo:table-cell>
				<fo:table-cell background-color="#EFFFF7"  border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt" white-space-treatment="preserve" white-space-collapse="false" linefeed-treatment="preserve">
					<xsl:value-of select="@output"/><xsl:text>&#xA0;</xsl:text>
					</fo:block>
				</fo:table-cell>
			</fo:table-row>
		</xsl:for-each>
	</fo:table-body>

</fo:table>

<fo:block font-size="6pt" font-family="sans-serif" padding-top="10pt">
<fo:basic-link internal-destination="head">Back to top</fo:basic-link>
</fo:block>

<fo:block>&#160;</fo:block>
	
</xsl:template>
<!-- ............................................................ -->

<!-- Post-Scan Script -->
<xsl:template match="postscript">
<fo:block font-family="sans-serif" font-size="11pt" font-weight="bold" padding-top="3pt" background-color="#F0F8FF" id="postscript">
Post-Scan Script Output
</fo:block>

<fo:block>&#160;</fo:block>

<fo:table>
	<fo:table-header>
		<fo:table-row>
			<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">Script Name</fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">Output</fo:block>
			</fo:table-cell>
		</fo:table-row>
	</fo:table-header>

	<fo:table-body>
		<xsl:for-each select="script">
			<fo:table-row>
				<fo:table-cell background-color="#EFFFF7"  border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">
					<xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text>
					</fo:block>
				</fo:table-cell>
				<fo:table-cell background-color="#EFFFF7"  border="solid black 1px" white-space-treatment="preserve" white-space-collapse="false" linefeed-treatment="preserve">
					<fo:block font-family="sans-serif" font-size="8pt">
					<xsl:value-of select="@output"/> <xsl:text>&#xA0;</xsl:text>
					</fo:block>
				</fo:table-cell>
			</fo:table-row>
		</xsl:for-each>
	</fo:table-body>

</fo:table>
	
<fo:block font-size="6pt" font-family="sans-serif" padding-top="10pt">
<fo:basic-link internal-destination="head">Back to top</fo:basic-link>
</fo:block>

<fo:block>&#160;</fo:block>
	
</xsl:template>
<!-- ............................................................ -->

<!-- Host-Scan Script -->
<xsl:template match="hostscript">

<fo:block>&#160;</fo:block>

<fo:block font-family="sans-serif" font-size="11pt" font-weight="bold" padding-top="3pt" background-color="#F0F8FF" id="hostscript.{generate-id()}">
Host-Scan Script Output
</fo:block>

<fo:block>&#160;</fo:block>

<fo:table>
	<fo:table-header>
		<fo:table-row>
			<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">Script Name</fo:block>
			</fo:table-cell>
			<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
				<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">Output</fo:block>
			</fo:table-cell>
		</fo:table-row>
	</fo:table-header>

	<fo:table-body>
		<xsl:for-each select="script">
			<fo:table-row>
				<fo:table-cell background-color="#EFFFF7"  border="solid black 1px">
					<fo:block font-family="sans-serif" font-size="8pt">
					<xsl:value-of select="@id"/>
					</fo:block>
				</fo:table-cell>
				<fo:table-cell background-color="#EFFFF7"  border="solid black 1px" white-space-treatment="preserve" white-space-collapse="false" linefeed-treatment="preserve">
					<fo:block font-family="sans-serif" font-size="8pt">
					<xsl:value-of select="@output"/> <xsl:text>&#xA0;</xsl:text>
					</fo:block>
				</fo:table-cell>
			</fo:table-row>
		</xsl:for-each>
	</fo:table-body>

</fo:table>

<fo:block font-size="6pt" font-family="sans-serif" padding-top="10pt">
<fo:basic-link internal-destination="head">back to top</fo:basic-link>
</fo:block>

<fo:block>&#160;</fo:block>
	
</xsl:template>
<!-- ............................................................ -->

<!-- smurf -->
<xsl:template match="smurf">
<xsl:if test="@responses != ''">
	<fo:block font-family="sans-serif" font-size="10pt" font-weight="bold" padding-top="10pt" padding-bottom="5pt">
	Smurf Responses
	</fo:block>

	<fo:block font-family="sans-serif" font-size="8pt">
	<xsl:value-of select="@responses" /> responses counted
	</fo:block>
</xsl:if>
</xsl:template>
<!-- ............................................................ -->

<!-- Traceroute -->
<xsl:template match="trace">
<xsl:if test="@proto">

<fo:block font-family="sans-serif" font-size="10pt" font-weight="bold" padding-top="10pt" padding-bottom="5pt" id="traceroute.{generate-id()}">
Traceroute Information
</fo:block>

<xsl:choose>
	<xsl:when test="@port">
		<fo:block font-family="sans-serif" font-size="8pt">
		Traceroute data generated using port <xsl:value-of select="@port" />/<xsl:value-of select="@proto"/>
		</fo:block>
	</xsl:when>

	<xsl:when test="@proto='icmp'">
		<fo:block font-family="sans-serif" font-size="8pt">
		Traceroute data generated using ICMP
		</fo:block>
	</xsl:when>
</xsl:choose>

<fo:table>
	<fo:table-header>
		<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
			<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">Hop</fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
			<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">RTT</fo:block>
		</fo:table-cell>
			<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
		<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">IP</fo:block>
		</fo:table-cell>
		<fo:table-cell background-color="#E1E1E1" border="solid black 1px">
			<fo:block font-family="sans-serif" font-size="8pt" font-weight="bold">Host</fo:block>
		</fo:table-cell>
	</fo:table-header>

	<fo:table-body>
		<xsl:for-each select="hop">
			<fo:table-row>
			<xsl:choose>
				<xsl:when test="@rtt = '--'">
					<fo:table-cell background-color="#F2F2F2" border="solid black 1px" width="25pt">
						<fo:block font-family="sans-serif" font-size="8pt"><xsl:value-of select="@ttl"/></fo:block>
					</fo:table-cell>
					<fo:table-cell background-color="#F2F2F2" border="solid black 1px" width="45pt">
						<fo:block font-family="sans-serif" font-size="8pt">--</fo:block>
					</fo:table-cell>
					<fo:table-cell background-color="#F2F2F2" border="solid black 1px" width="70pt">
						<fo:block font-family="sans-serif" font-size="8pt"><xsl:value-of select="@ipaddr"/></fo:block>
					</fo:table-cell>
					<fo:table-cell background-color="#F2F2F2" border="solid black 1px">
						<fo:block font-family="sans-serif" font-size="8pt"><xsl:value-of select="@host"/></fo:block>
					</fo:table-cell>
				</xsl:when>

				<xsl:when test="@rtt > 0">
					<fo:table-cell background-color="#CCFFCC" border="solid black 1px" width="25pt">
						<fo:block font-family="sans-serif" font-size="8pt"><xsl:value-of select="@ttl"/></fo:block>
					</fo:table-cell>
					<fo:table-cell background-color="#CCFFCC" border="solid black 1px" width="45pt">
						<fo:block font-family="sans-serif" font-size="8pt"><xsl:value-of select="@rtt"/></fo:block>
					</fo:table-cell>
					<fo:table-cell background-color="#CCFFCC" border="solid black 1px" width="70pt">
						<fo:block font-family="sans-serif" font-size="8pt"><xsl:value-of select="@ipaddr"/></fo:block>
					</fo:table-cell>
					<fo:table-cell background-color="#CCFFCC" border="solid black 1px">
						<fo:block font-family="sans-serif" font-size="8pt"><xsl:value-of select="@host"/></fo:block>
					</fo:table-cell>
				</xsl:when>

				<xsl:otherwise>
					<fo:table-cell border="solid black 1px" background-color="#F2F2F2" width="25pt">
						<fo:block font-family="sans-serif" font-size="8pt"><xsl:value-of select="@ttl"/></fo:block>
					</fo:table-cell>
				</xsl:otherwise>
				</xsl:choose>
				</fo:table-row>
		</xsl:for-each>
	</fo:table-body>

</fo:table>

</xsl:if>

</xsl:template>
<!-- ............................................................ -->

</xsl:stylesheet>
