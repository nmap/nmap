<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		xmlns:xslthl="http://xslthl.sf.net"
                exclude-result-prefixes="xslthl"
                version='1.0'>

<!-- ********************************************************************
     $Id: highlight.xsl 8419 2009-04-29 20:37:52Z kosek $
     ********************************************************************

     This file is part of the XSL DocBook Stylesheet distribution.
     See ../README or http://docbook.sf.net/release/xsl/current/ for
     and other information.

     ******************************************************************** -->

<xsl:import href="../highlighting/common.xsl"/>

<xsl:template match='xslthl:keyword' mode="xslthl">
  <b class="hl-keyword"><xsl:apply-templates mode="xslthl"/></b>
</xsl:template>

<xsl:template match='xslthl:string' mode="xslthl">
  <b class="hl-string"><i style="color:red"><xsl:apply-templates mode="xslthl"/></i></b>
</xsl:template>

<xsl:template match='xslthl:comment' mode="xslthl">
  <i class="hl-comment" style="color: silver"><xsl:apply-templates mode="xslthl"/></i>
</xsl:template>

<xsl:template match='xslthl:directive' mode="xslthl">
  <span class="hl-directive" style="color: maroon"><xsl:apply-templates mode="xslthl"/></span>
</xsl:template>

<xsl:template match='xslthl:tag' mode="xslthl">
  <b class="hl-tag" style="color: #000096"><xsl:apply-templates mode="xslthl"/></b>
</xsl:template>

<xsl:template match='xslthl:attribute' mode="xslthl">
  <span class="hl-attribute" style="color: #F5844C"><xsl:apply-templates mode="xslthl"/></span>
</xsl:template>

<xsl:template match='xslthl:value' mode="xslthl">
  <span class="hl-value" style="color: #993300"><xsl:apply-templates mode="xslthl"/></span>
</xsl:template>

<xsl:template match='xslthl:html' mode="xslthl">
  <b><i style="color: red"><xsl:apply-templates mode="xslthl"/></i></b>
</xsl:template>

<xsl:template match='xslthl:xslt' mode="xslthl">
  <b style="color: #0066FF"><xsl:apply-templates mode="xslthl"/></b>
</xsl:template>

<!-- Not emitted since XSLTHL 2.0 -->
<xsl:template match='xslthl:section' mode="xslthl">
  <b><xsl:apply-templates mode="xslthl"/></b>
</xsl:template>

<xsl:template match='xslthl:number' mode="xslthl">
  <span class="hl-number"><xsl:apply-templates mode="xslthl"/></span>
</xsl:template>

<xsl:template match='xslthl:annotation' mode="xslthl">
  <i><span class="hl-annotation" style="color: gray"><xsl:apply-templates mode="xslthl"/></span></i>
</xsl:template>

<!-- Not sure which element will be in final XSLTHL 2.0 -->
<xsl:template match='xslthl:doccomment|xslthl:doctype' mode="xslthl">
  <b class="hl-tag" style="color: blue"><xsl:apply-templates mode="xslthl"/></b>
</xsl:template>

</xsl:stylesheet>