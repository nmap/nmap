<?xml version="1.0"?>
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
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format">
<xsl:output 
  method="html" 
  indent="yes" 
  encoding="UTF-8" 
	doctype-public="-//W3C//DTD HTML 4.01//EN"
	doctype-system="http://www.w3.org/TR/html4/strict.dtd"
  
/>

<!-- global variables      -->
<!-- ............................................................ -->
<xsl:variable name="nmap_xsl_version">0.9c</xsl:variable>
<!-- ............................................................ -->
<xsl:variable name="start"><xsl:value-of select="/nmaprun/@startstr" /></xsl:variable>
<xsl:variable name="end"><xsl:value-of select="/nmaprun/runstats/finished/@timestr" /> </xsl:variable>
<xsl:variable name="totaltime"><xsl:value-of select="/nmaprun/runstats/finished/@time -/nmaprun/@start" /></xsl:variable>
<xsl:key name="portstatus" match="@state" use="."/>
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
  #menu {
    display:none;
  }

  body {
    font-family: Verdana, Helvetica, sans-serif;
  }
  
  h1 {
    font-size: 13pt;
    font-weight:bold;
    margin:4pt 0pt 0pt 0pt;
    padding:0;
  }

  h2 {
    font-size: 12pt;
    font-weight:bold;
    margin:3pt 0pt 0pt 0pt;
    padding:0;
  }

  h3, a:link, a:visited {
    font-size: 9pt;
    font-weight:bold;
    margin:1pt 0pt 0pt 20pt;
    padding:0;
    text-decoration: none;
    color: #000000;
  }

  p,ul {
    font-size: 9pt;
    margin:1pt 0pt 8pt 40pt;
    padding:0;
    text-align:left;
  }

  li {
    font-size: 9pt;
    margin:0;
    padding:0;
    text-align:left;
  }

  table {
    margin:1pt 0pt 8pt 40pt;
    border:0px;
    width:90%
  }

  td {
    border:0px;
    border-top:1px solid black;
    font-size: 9pt;
  }

  .head td {
    border:0px;
    font-weight:bold;
    font-size: 9pt;
  }
  .noprint { display: none; }
}

/* stylesheet screen */
@media screen
{
  body {
    font-family: Verdana, Helvetica, sans-serif;
    margin: 0px;
    background-color: #FFFFFF;
    color: #000000;
    text-align: center;
  }

  #container {
    text-align:left;
    margin: 10px auto;
    width: 90%;
  }

  h1 {
    font-family: Verdana, Helvetica, sans-serif;
    font-weight:bold;
    font-size: 14pt;
    color: #FFFFFF;
    background-color:#2A0D45;
    margin:10px 0px 0px 0px;
    padding:5px 4px 5px 4px;
    width: 100%;
    border:1px solid black;
    text-align: left;
  }

  h2 {
    font-family: Verdana, Helvetica, sans-serif;
    font-weight:bold;
    font-size: 11pt;
    color: #000000;
    margin:30px 0px 0px 0px;
    padding:4px;
    width: 100%;
    background-color:#F0F8FF;
    text-align: left;
  }

  h2.green {
    color: #000000;
    background-color:#CCFFCC;
    border-color:#006400;
  }

  h2.red {
    color: #000000;
    background-color:#FFCCCC;
    border-color:#8B0000;
  }
   
  h3 {
    font-family: Verdana, Helvetica, sans-serif;
    font-weight:bold;
    font-size: 10pt;
    color:#000000;
    background-color: #FFFFFF;
    width: 75%;
    text-align: left;
  }

  p {
    font-family: Verdana, Helvetica, sans-serif;
    font-size: 8pt;
    color:#000000;
    background-color: #FFFFFF;
    width: 75%;
    text-align: left;
  }

  p i {
    font-family: Verdana, Helvetica, sans-serif;
    font-size: 8pt;
    color:#000000;
    background-color: #CCCCCC;
  }

  ul {
    font-family: Verdana, Helvetica, sans-serif;
    font-size: 8pt;
    color:#000000;
    background-color: #FFFFFF;
    width: 75%;
    text-align: left;
  }

  a {
    font-family: Verdana, Helvetica, sans-serif;
    text-decoration: none;
    font-size: 8pt;
    color:#000000;
    font-weight:bold;
    background-color: #FFFFFF;
    color: #000000;
  }

  li a {
    font-family: Verdana, Helvetica, sans-serif;
    text-decoration: none;
    font-size: 10pt;
    color:#000000;
    font-weight:bold;
    background-color: #FFFFFF;
    color: #000000;
  }

  a:hover {
    text-decoration: underline;
  }

  a.up {
      color:#006400;
  }

  table {
    width: 80%;
    border:0px;
    color: #000000;
    background-color: #000000;
    margin:10px;
  }

  tr {
    vertical-align:top;
    font-family: Verdana, Helvetica, sans-serif;
    font-size: 8pt;
    color:#000000;
    background-color: #FFFFFF;
  }

  tr.head {
    background-color: #E1E1E1;
    color: #000000;
    font-weight:bold;
  }

  tr.open {
    background-color: #CCFFCC;
    color: #000000;
  }
	
  tr.script {
    background-color: #EFFFF7;
    color: #000000;
  }

  tr.filtered {
    background-color: #F2F2F2;
    color: #000000;
  }

  tr.closed {
    background-color: #F2F2F2;
    color: #000000;
  }
    
  td {
    padding:2px;
  }
        
  #menu li {
    display         : inline;
    margin          : 0;
    /*margin-right    : 10px;*/
    padding         : 0;
    list-style-type : none;
  }    
 
  #menubox {
    position: fixed;
    bottom: 0px;
    right: 0px;
    width: 120px;
  }
  
  
  <![CDATA[
  /* This section handle's IE's refusal to honor the fixed CSS attribute */
  
  * html div#menubox {
    position: absolute;
    top:expression(eval(
      document.compatMode && document.compatMode=='CSS1Compat') ?
      documentElement.scrollTop+(documentElement.clientHeight-this.clientHeight) 
      : document.body.scrollTop +(document.body.clientHeight-this.clientHeight));
  }
  /* This fixes the jerky effect when scrolling in IE*/
  * html,* html body {
    background: #fff url(nosuchfile) fixed;
  }

  ]]>
 
  .up {
    color: #000000;
    background-color:#CCFFCC;
  }
  
  .down {
    color:#626262;
    background-color: #F2F2F2;
  }

  .print_only { display: none; }
  .hidden { display: none; }
  .unhidden { display: block; }
  
}
</style>

  <title>Nmap Scan Report - Scanned at <xsl:value-of select="$start" /></title>
	
   
    <script type="text/javascript">
     
      <![CDATA[
                
      function toggle(divID) {
        var item = document.getElementById(divID);
        if (item) {
          item.className=(item.className=='hidden')?'unhidden':'hidden';
        }
      }
           
      function togglePorts(tableID,portState) {
        var table = document.getElementById(tableID);    
        var tbody = table.getElementsByTagName("tbody")[0];
        var rows = tbody.getElementsByTagName("tr");
        for (var i=0; i < rows.length; i++) {
          var value = rows[i].getElementsByTagName("td")[2].firstChild.nodeValue;
          if (value == portState) {
            rows[i].style.display = (rows[i].style.display == 'none')?'':'none';
          }
        }
      }
      
      function toggleAll(portState) {
        var allTables = document.getElementsByTagName("table");
        for (var c=0; c < allTables.length; c++) {
          if (allTables[c].id != "") {
            togglePorts(allTables[c].id, portState)
          }
        }
      }
      
      function init (){
        toggleAll('closed');
        toggleAll('filtered');     
      }     
            
      window.onload = init; 
      
      ]]>
    
    </script>
    	
</head>

<body>
  <a name="top" />
  <div id="container">

    <h1>Nmap Scan Report - Scanned at <xsl:value-of select="$start" /></h1>
    
    <ul id="menu">
      <li><a href="#scansummary">Scan Summary</a></li>

      <xsl:if test="prescript/script/@id">
        <li>
          <xsl:text> | </xsl:text>
          <a href="#prescript">Pre-Scan Script Output</a>
        </li>
      </xsl:if>
			
      <xsl:for-each select="host">
        <xsl:sort select="substring ( address/@addr, 1, string-length ( substring-before ( address/@addr, '.' ) ) )* (256*256*256) + substring ( substring-after ( address/@addr, '.' ), 1, string-length ( substring-before ( substring-after ( address/@addr, '.' ), '.' ) ) )* (256*256) + substring ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), 1, string-length ( substring-before ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ) ) ) * 256 + substring ( substring-after ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ), 1 )" order="ascending" data-type="number"/>

        <li>
          <xsl:text> | </xsl:text>
          <xsl:element name="a">
            <xsl:attribute name="href">#host_<xsl:value-of select="translate(address/@addr, '.', '_') " /></xsl:attribute>
            <xsl:attribute name="class">
              <xsl:choose>
                <xsl:when test="status/@state = 'up'">up</xsl:when>
                <xsl:otherwise>down</xsl:otherwise>
              </xsl:choose>
            </xsl:attribute>
                    
            <xsl:variable name="var_address" select="address/@addr" />
            <xsl:if test="count(hostnames/hostname) > 0">
              <xsl:for-each select="hostnames">
                <xsl:choose>

                  <xsl:when test="hostname/@type='user'">
                    <xsl:value-of select="hostname/@name"/>
                    (<xsl:value-of select="$var_address"/>)
                  </xsl:when>

                  <xsl:otherwise>
                    <xsl:for-each select="hostname/@name[hostname/@type='PTR']"/>
                    <xsl:value-of select="hostname/@name"/> (<xsl:value-of select="$var_address"/>)
                  </xsl:otherwise>

                </xsl:choose>
              </xsl:for-each>
            </xsl:if>

            <xsl:if test="count(hostnames/hostname) = 0">
              <xsl:value-of select="address/@addr"/>
            </xsl:if>
          </xsl:element>


        </li>
      </xsl:for-each>

      <xsl:if test="postscript/script/@id">
        <li> <xsl:text> | </xsl:text> <a href="#postscript">Post-Scan Script Output</a> </li>
      </xsl:if>
    </ul>

    <xsl:element name="a">
      <xsl:attribute name="name">scansummary</xsl:attribute>
    </xsl:element>
    
    <hr class="print_only" />
    
    <h2>Scan Summary</h2>

    <p>
      Nmap <xsl:value-of select="@version" /> was initiated at <xsl:value-of select="$start" /> with these arguments:<br/>
      <i><xsl:value-of select="@args" /></i><br/>
    </p>
    <p>
    Verbosity: <xsl:value-of select="verbose/@level" />; Debug level <xsl:value-of select="debugging/@level" />
    </p>

    <p>
    <xsl:value-of select="/nmaprun/runstats/finished/@summary" />
    </p>

    <xsl:apply-templates select="prescript"/>

    <xsl:apply-templates select="host">
      <xsl:sort select="substring ( address/@addr, 1, string-length ( substring-before ( address/@addr, '.' ) ) )* (256*256*256) + substring ( substring-after ( address/@addr, '.' ), 1, string-length ( substring-before ( substring-after ( address/@addr, '.' ), '.' ) ) )* (256*256) + substring ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), 1, string-length ( substring-before ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ) ) ) * 256 + substring ( substring-after ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ), 1 )" order="ascending" data-type="number"/>
    </xsl:apply-templates>
	
    <xsl:apply-templates select="postscript"/>
   
  </div>
    
  <div id="menubox" class="noprint">
    <a href="#top"><small>Go to top</small></a> <br />
    <a href="javascript:toggleAll('closed');"><small>Toggle Closed Ports</small></a><br />
    <a href="javascript:toggleAll('filtered');"><small>Toggle Filtered Ports</small></a>
  </div>
</body>
</html>
</xsl:template>
<!-- ............................................................ -->

<!-- host -->
<!-- ............................................................ -->
<xsl:template match="host">

  <hr class="print_only" />
  
  <xsl:variable name="var_address" select="address/@addr" />
  
  <xsl:element name="a">
    <xsl:attribute name="name">host_<xsl:value-of select="translate(address/@addr, '.', '_') " /></xsl:attribute>
  </xsl:element>

  <xsl:choose>

    <xsl:when test="status/@state = 'up'">
      <h2 class="up"><xsl:value-of select="address/@addr"/>

      <xsl:if test="count(hostnames/hostname) > 0">
        <xsl:for-each select="hostnames/hostname">
          <xsl:sort select="@name" order="ascending" data-type="text"/>
            <xsl:text> / </xsl:text><xsl:value-of select="@name"/>
        </xsl:for-each>
      </xsl:if>

      <span class="print_only">(online)</span>
      </h2>

    </xsl:when>

    <xsl:otherwise>
      <h2 class="down"><xsl:value-of select="address/@addr"/>

      <xsl:if test="count(hostnames/hostname) > 0">
        <xsl:for-each select="hostnames/hostname">
          <xsl:sort select="@name" order="ascending" data-type="text"/>
            <xsl:text> / </xsl:text><xsl:value-of select="@name"/>
        </xsl:for-each>
      </xsl:if>

      <xsl:element name="a">
        <xsl:attribute name="href">javascript:toggle('hostblock_<xsl:value-of select="$var_address"/>');</xsl:attribute>
        <xsl:attribute name="class">host_down</xsl:attribute>
        <span class="noprint"><small> (click to expand)</small></span>
      </xsl:element>
      <span class="print_only">(offline)</span></h2>
    </xsl:otherwise>

  </xsl:choose>

  
  <xsl:element name="div">
    <xsl:attribute name="id">hostblock_<xsl:value-of select="$var_address"/></xsl:attribute>
    <xsl:choose>

      <xsl:when test="status/@state = 'up'">
        <xsl:attribute name="class">unhidden</xsl:attribute>
      </xsl:when>

      <xsl:otherwise>
        <xsl:attribute name="class">hidden</xsl:attribute>
      </xsl:otherwise>
    </xsl:choose>


  <xsl:if test="count(address) > 0">
    <h3>Address</h3>

      <ul>
        <xsl:for-each select="address">
          <li><xsl:value-of select="@addr"/>
            <xsl:if test="@vendor">
              <xsl:text> - </xsl:text>
                <xsl:value-of select="@vendor"/>
              <xsl:text> </xsl:text>
            </xsl:if>
            (<xsl:value-of select="@addrtype"/>)
          </li>
        </xsl:for-each>
      </ul>
  </xsl:if>
    
	
  <xsl:apply-templates/>

  <br />
  
  <xsl:element name="a">
    <xsl:attribute name="href">javascript:toggle('metrics_<xsl:value-of select="$var_address"/>');</xsl:attribute>
    Misc Metrics <span class="noprint"><small> (click to expand)</small></span>
  </xsl:element>
  
  
  <xsl:element name="div">
    <xsl:attribute name="id">metrics_<xsl:value-of select="$var_address"/></xsl:attribute>
    <xsl:attribute name="class">hidden</xsl:attribute>
		
    <table cellspacing="1">
      <tr class="head">
        <td>Metric</td>
        <td>Value</td>
      </tr>
		
      <tr>
        <td>Ping Results</td>
        <td><xsl:value-of select="status/@reason"/>
          <xsl:if test="status/@reasonsrc">
            <xsl:text> from </xsl:text>
            <xsl:value-of select="status/@reasonsrc"/>
          </xsl:if>
        </td>
      </tr>
			
    <xsl:if test="uptime/@seconds != ''">
      <tr>
        <td>System Uptime</td>
        <td><xsl:value-of select="uptime/@seconds" /> seconds  (last reboot: <xsl:value-of select="uptime/@lastboot" />)
        </td>
      </tr>
    </xsl:if>
		
    <xsl:if test="distance/@value != ''">
      <tr>
        <td>Network Distance</td>
        <td><xsl:value-of select="distance/@value" /> hops</td>
      </tr>
    </xsl:if>
		
		
    <xsl:if test="tcpsequence/@index != ''">
      <tr>
        <td>TCP Sequence Prediction</td>
        <td>Difficulty=<xsl:value-of select="tcpsequence/@index" /> (<xsl:value-of select="tcpsequence/@difficulty" />)</td>
      </tr>
    </xsl:if>
		
    <xsl:if test="ipidsequence/@class != ''">
      <tr>
        <td>IP ID Sequence Generation</td>
        <td><xsl:value-of select="ipidsequence/@class" /></td>
      </tr>
    </xsl:if>
		
      </table>
    </xsl:element>

  </xsl:element>
	
</xsl:template>
<!-- ............................................................ -->



<!-- hostnames -->
<!-- ............................................................ -->
<xsl:template match="hostnames">
  <xsl:if test="hostname/@name != ''"><h3>Hostnames</h3><ul>	<xsl:apply-templates/></ul></xsl:if>
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
  <xsl:variable name="var_address" select="../address/@addr" />
  <h3>Ports</h3>
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
  
    
    <xsl:for-each select="port/state/@state[generate-id()=generate-id(key('portstatus',.))]" />
    <xsl:variable name="closed_count" select="count(port/state[@state='closed'])" />
    <xsl:variable name="filtered_count" select="count(port/state[@state='filtered'])" />
     
  
    <xsl:element name="table">
      <xsl:attribute name="id">porttable_<xsl:value-of select="$var_address"/></xsl:attribute>
      <xsl:attribute name="cellspacing">1</xsl:attribute>
    
    <tr class="head">
        <td colspan="2">Port</td>
        <td>State 
          <xsl:element name="a">
            <xsl:attribute name="href">javascript:togglePorts('porttable_<xsl:value-of select="$var_address"/>','closed');</xsl:attribute>
            <span class="noprint"><small> (toggle closed [<xsl:value-of select="$closed_count"/>] </small></span>
          </xsl:element>
          <xsl:element name="a">
            <xsl:attribute name="href">javascript:togglePorts('porttable_<xsl:value-of select="$var_address"/>','filtered');</xsl:attribute>
            <span class="noprint"><small> | filtered [<xsl:value-of select="$filtered_count"/>])</small></span>
          </xsl:element>
        </td>
        <td>Service</td>
        <td>Reason</td>
        <td>Product</td>
        <td>Version</td>
        <td>Extra info</td>
      </tr>

      <xsl:apply-templates/>
    </xsl:element>
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
        <tr class="script">
          <td></td>
          <td><xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text></td>
          <td colspan="6">
            <pre><xsl:value-of select="@output"/> <xsl:text>&#xA0;</xsl:text></pre>
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
  <h3>Remote Operating System Detection</h3>
		
  <xsl:if test="count(osmatch) = 0"><p>Unable to identify operating system.</p></xsl:if>

  <ul>
    <xsl:for-each select="portused">
      <li>Used port: <b><xsl:value-of select="@portid" />/<xsl:value-of select="@proto" /> </b> (<b><xsl:value-of select="@state" /></b>)  </li>
    </xsl:for-each>
    
    <xsl:for-each select="osmatch">
      <li>OS match: <b><xsl:value-of select="@name" /> </b> (<b><xsl:value-of select="@accuracy" />%</b>)</li>
    </xsl:for-each>
  </ul>
  
  <xsl:apply-templates select="osfingerprint"/>

</xsl:template>
<!-- ............................................................ -->


<!-- osfingerprint -->
<!-- ............................................................ -->
<xsl:template match="osfingerprint">

  <xsl:variable name="var_address" select="../../address/@addr" /> 

  <xsl:choose>
    <xsl:when test="count(../osmatch)=0">
      
      <ul>
        <li>Cannot determine exact operating system.  Fingerprint provided below.</li>
        <li>If you know what OS is running on it, see https://nmap.org/submit/</li>
      </ul>
      <table cellspacing="1">
        <tr class="head">
          <td>Operating System fingerprint</td>
        </tr>
        <tr>
          <td><pre><xsl:value-of select="@fingerprint" /></pre></td>
        </tr>
      </table>
      
    </xsl:when>

    <xsl:otherwise>
      <ul>
        <li class="noprint">OS identified but the fingerprint was requested at scan time. 
          
        <xsl:element name="a">
          <xsl:attribute name="href">javascript:toggle('osblock_<xsl:value-of select="$var_address"/>');</xsl:attribute>
          <span class="noprint"><small> (click to expand)</small></span>
        </xsl:element>
        </li>
      </ul>

      <xsl:element name="div">
        <xsl:attribute name="id">osblock_<xsl:value-of select="$var_address"/></xsl:attribute>
        <xsl:attribute name="class">hidden</xsl:attribute>

        <table class="noprint" cellspacing="1">
          <tr class="head">
            <td>Operating System fingerprint</td>
          </tr>
          <tr>
            <td><pre><xsl:value-of select="@fingerprint" /></pre></td>
          </tr>
        </table>      
      
      </xsl:element>
      
    </xsl:otherwise>

  </xsl:choose>

  </xsl:template>
<!-- ............................................................ -->

<!-- Pre-Scan script -->
<!-- ............................................................ -->
<xsl:template match="prescript">

  <hr class="print_only" />
  
  <xsl:element name="a">
    <xsl:attribute name="name">prescript</xsl:attribute>
  </xsl:element>

  <h2>Pre-Scan Script Output</h2>

  <table>
    <tr class="head">
      <td>Script Name</td>
      <td>Output</td>
    </tr>
    <xsl:for-each select="script">

    <tr class="script">
      <td>
        <xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text>
      </td>
      <td>
        <pre>
          <xsl:value-of select="@output"/> <xsl:text></xsl:text>
        </pre>
      </td>
    </tr>

  </xsl:for-each>
  </table>
</xsl:template>
<!-- ............................................................ -->

<!-- Post-Scan script -->
<!-- ............................................................ -->
<xsl:template match="postscript">

  <hr class="print_only" />
  
  <xsl:element name="a">
    <xsl:attribute name="name">postscript</xsl:attribute>
  </xsl:element>

  <h2>Post-Scan Script Putput</h2>
	
  <table>
    <tr class="head">
      <td>Script Name</td>
      <td>Output</td>
    </tr>

  <xsl:for-each select="script">
    <tr class="script">
      <td>
        <xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text>
      </td>
      <td>
        <pre>
          <xsl:value-of select="@output"/> <xsl:text></xsl:text>
        </pre>
      </td>
    </tr>

  </xsl:for-each>
  </table>
</xsl:template>
<!-- ............................................................ -->


<!-- Host Script Scan -->
<!-- ............................................................ -->
<xsl:template match="hostscript">
  <h3>Host Script Output</h3>

    <table>
      <tr class="head">
        <td>Script Name</td>
        <td>Output</td>
      </tr>

  <xsl:for-each select="script">
      <tr class="script">
        <td>
          <xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text>
        </td>
        <td>
          <pre>
            <xsl:value-of select="@output"/> <xsl:text>&#xA0;</xsl:text>
          </pre>
        </td>
      </tr>
  </xsl:for-each>

    </table>
</xsl:template>
<!-- ............................................................ -->

<!-- smurf -->
<!-- ............................................................ -->
<xsl:template match="smurf">
  <xsl:if test="@responses != ''"><h3>Smurf Responses</h3>
    <ul>
      <li><xsl:value-of select="@responses" /> responses counted</li>
    </ul>
  </xsl:if>
</xsl:template>
<!-- ............................................................ -->


<!-- traceroute -->
<!-- ............................................................ -->

<xsl:template match="trace">
  <xsl:if test="@port">
  <xsl:variable name="var_address" select="../address/@addr" /> 
 

  
 <xsl:element name="a">
    <xsl:attribute name="href">javascript:toggle('trace_<xsl:value-of select="$var_address"/>');</xsl:attribute>
    Traceroute Information <span class="noprint"><small> (click to expand)</small></span>
  </xsl:element>

  <xsl:element name="div">
    <xsl:attribute name="id">trace_<xsl:value-of select="$var_address"/></xsl:attribute>
    <xsl:attribute name="class">hidden</xsl:attribute>

  
    <xsl:choose>
      <xsl:when test="@port">
        <ul><li>Traceroute data generated using port <xsl:value-of select="@port" />/<xsl:value-of select="@proto" /></li></ul>
      </xsl:when>
    </xsl:choose>
  
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
  </xsl:element>

  </xsl:if>
</xsl:template>
<!-- ............................................................ -->
</xsl:stylesheet>
