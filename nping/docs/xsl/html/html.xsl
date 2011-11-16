<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version='1.0'>

<!-- ********************************************************************
     $Id: html.xsl 8421 2009-05-04 07:49:49Z bobstayton $
     ********************************************************************

     This file is part of the XSL DocBook Stylesheet distribution.
     See ../README or http://docbook.sf.net/release/xsl/current/ for
     copyright and other information.

     ******************************************************************** -->

<!-- These variables set the align attribute value for HTML output based on
     the writing-mode specified in the gentext file for the document's lang. -->

<xsl:variable name="direction.align.start">
  <xsl:choose>
    <xsl:when test="starts-with($writing.mode, 'lr')">left</xsl:when>
    <xsl:when test="starts-with($writing.mode, 'rl')">right</xsl:when>
    <xsl:otherwise>left</xsl:otherwise>
  </xsl:choose>
</xsl:variable>

<xsl:variable name="direction.align.end">
  <xsl:choose>
    <xsl:when test="starts-with($writing.mode, 'lr')">right</xsl:when>
    <xsl:when test="starts-with($writing.mode, 'rl')">left</xsl:when>
    <xsl:otherwise>right</xsl:otherwise>
  </xsl:choose>
</xsl:variable>

<xsl:variable name="direction.mode">
  <xsl:choose>
    <xsl:when test="starts-with($writing.mode, 'lr')">ltr</xsl:when>
    <xsl:when test="starts-with($writing.mode, 'rl')">rtl</xsl:when>
    <xsl:otherwise>ltr</xsl:otherwise>
  </xsl:choose>
</xsl:variable>

<!-- The generate.html.title template is currently used for generating HTML -->
<!-- "title" attributes for some inline elements only, but not for any -->
<!-- block elements. It is called in eleven places in the inline.xsl -->
<!-- file. But it's called by all the inline.* templates (e.g., -->
<!-- inline.boldseq), which in turn are called by other (element) -->
<!-- templates, so it results, currently, in supporting generation of the -->
<!-- HTML "title" attribute for a total of about 92 elements. -->
<!-- You can use mode="html.title.attribute" to get a title for -->
<!-- an element specified by a param, including targets of cross references. -->
<xsl:template name="generate.html.title">
  <xsl:apply-templates select="." mode="html.title.attribute"/>
</xsl:template>

<!-- Generate a title attribute for the context node -->
<xsl:template match="*" mode="html.title.attribute">
  <xsl:variable name="is.title">
    <xsl:call-template name="gentext.template.exists">
      <xsl:with-param name="context" select="'title'"/>
      <xsl:with-param name="name" select="local-name(.)"/>
      <xsl:with-param name="lang">
        <xsl:call-template name="l10n.language"/>
      </xsl:with-param>
    </xsl:call-template>
  </xsl:variable>

  <xsl:variable name="is.title-numbered">
    <xsl:call-template name="gentext.template.exists">
      <xsl:with-param name="context" select="'title-numbered'"/>
      <xsl:with-param name="name" select="local-name(.)"/>
      <xsl:with-param name="lang">
        <xsl:call-template name="l10n.language"/>
      </xsl:with-param>
    </xsl:call-template>
  </xsl:variable>

  <xsl:variable name="is.title-unnumbered">
    <xsl:call-template name="gentext.template.exists">
      <xsl:with-param name="context" select="'title-unnumbered'"/>
      <xsl:with-param name="name" select="local-name(.)"/>
      <xsl:with-param name="lang">
        <xsl:call-template name="l10n.language"/>
      </xsl:with-param>
    </xsl:call-template>
  </xsl:variable>

  <xsl:variable name="has.title.markup">
    <xsl:apply-templates select="." mode="title.markup">
      <xsl:with-param name="verbose" select="0"/>
    </xsl:apply-templates>
  </xsl:variable>

  <xsl:variable name="gentext.title">
    <xsl:if test="$has.title.markup != '???TITLE???' and
                  ($is.title != 0 or
                  $is.title-numbered != 0 or
                  $is.title-unnumbered != 0)">
      <xsl:apply-templates select="."
                           mode="object.title.markup.textonly"/>
    </xsl:if>
  </xsl:variable>

  <xsl:choose>
    <xsl:when test="string-length($gentext.title) != 0">
      <xsl:attribute name="title">
        <xsl:value-of select="$gentext.title"/>
      </xsl:attribute>
    </xsl:when>
    <!-- Fall back to alt if available -->
    <xsl:when test="alt">
      <xsl:attribute name="title">
        <xsl:value-of select="normalize-space(alt)"/>
      </xsl:attribute>
    </xsl:when>
  </xsl:choose>
</xsl:template>

<xsl:template match="qandaentry" mode="html.title.attribute">
  <xsl:apply-templates select="question" mode="html.title.attribute"/>
</xsl:template>

<xsl:template match="question" mode="html.title.attribute">
  <xsl:variable name="label.text">
    <xsl:apply-templates select="." mode="qanda.label"/>
  </xsl:variable>

  <xsl:choose>
    <xsl:when test="string-length($label.text) != 0">
      <xsl:attribute name="title">
        <xsl:value-of select="$label.text"/>
      </xsl:attribute>
    </xsl:when>
    <!-- Fall back to alt if available -->
    <xsl:when test="alt">
      <xsl:attribute name="title">
        <xsl:value-of select="normalize-space(alt)"/>
      </xsl:attribute>
    </xsl:when>
  </xsl:choose>
</xsl:template>

<xsl:template name="dir">
  <xsl:param name="inherit" select="0"/>

  <xsl:variable name="dir">
    <xsl:choose>
      <xsl:when test="@dir">
        <xsl:value-of select="@dir"/>
      </xsl:when>
      <xsl:when test="$inherit != 0">
        <xsl:value-of select="ancestor::*/@dir[1]"/>
      </xsl:when>
    </xsl:choose>
  </xsl:variable>

  <xsl:if test="$dir != ''">
    <xsl:attribute name="dir">
      <xsl:value-of select="$dir"/>
    </xsl:attribute>
  </xsl:if>
</xsl:template>

<xsl:template name="anchor">
  <xsl:param name="node" select="."/>
  <xsl:param name="conditional" select="1"/>
  <xsl:variable name="id">
    <xsl:call-template name="object.id">
      <xsl:with-param name="object" select="$node"/>
    </xsl:call-template>
  </xsl:variable>
  <xsl:if test="$conditional = 0 or $node/@id or $node/@xml:id">
    <a name="{$id}"/>
  </xsl:if>
</xsl:template>

<xsl:template name="href.target.uri">
  <xsl:param name="context" select="."/>
  <xsl:param name="object" select="."/>
  <xsl:text>#</xsl:text>
  <xsl:call-template name="object.id">
    <xsl:with-param name="object" select="$object"/>
  </xsl:call-template>
</xsl:template>

<xsl:template name="href.target">
  <xsl:param name="context" select="."/>
  <xsl:param name="object" select="."/>
  <xsl:text>#</xsl:text>
  <xsl:call-template name="object.id">
    <xsl:with-param name="object" select="$object"/>
  </xsl:call-template>
</xsl:template>

<xsl:template name="href.target.with.base.dir">
  <xsl:param name="context" select="."/>
  <xsl:param name="object" select="."/>
  <xsl:if test="$manifest.in.base.dir = 0">
    <xsl:value-of select="$base.dir"/>
  </xsl:if>
  <xsl:call-template name="href.target">
    <xsl:with-param name="context" select="$context"/>
    <xsl:with-param name="object" select="$object"/>
  </xsl:call-template>
</xsl:template>

<xsl:template name="dingbat">
  <xsl:param name="dingbat">bullet</xsl:param>
  <xsl:call-template name="dingbat.characters">
    <xsl:with-param name="dingbat" select="$dingbat"/>
  </xsl:call-template>
</xsl:template>

<xsl:template name="dingbat.characters">
  <!-- now that I'm using the real serializer, all that dingbat malarky -->
  <!-- isn't necessary anymore... -->
  <xsl:param name="dingbat">bullet</xsl:param>
  <xsl:choose>
    <xsl:when test="$dingbat='bullet'">&#x2022;</xsl:when>
    <xsl:when test="$dingbat='copyright'">&#x00A9;</xsl:when>
    <xsl:when test="$dingbat='trademark'">&#x2122;</xsl:when>
    <xsl:when test="$dingbat='trade'">&#x2122;</xsl:when>
    <xsl:when test="$dingbat='registered'">&#x00AE;</xsl:when>
    <xsl:when test="$dingbat='service'">(SM)</xsl:when>
    <xsl:when test="$dingbat='nbsp'">&#x00A0;</xsl:when>
    <xsl:when test="$dingbat='ldquo'">&#x201C;</xsl:when>
    <xsl:when test="$dingbat='rdquo'">&#x201D;</xsl:when>
    <xsl:when test="$dingbat='lsquo'">&#x2018;</xsl:when>
    <xsl:when test="$dingbat='rsquo'">&#x2019;</xsl:when>
    <xsl:when test="$dingbat='em-dash'">&#x2014;</xsl:when>
    <xsl:when test="$dingbat='mdash'">&#x2014;</xsl:when>
    <xsl:when test="$dingbat='en-dash'">&#x2013;</xsl:when>
    <xsl:when test="$dingbat='ndash'">&#x2013;</xsl:when>
    <xsl:otherwise>
      <xsl:text>&#x2022;</xsl:text>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>

<xsl:template name="id.warning">
  <xsl:if test="$id.warnings != 0 and not(@id) and not(@xml:id) and parent::*">
    <xsl:variable name="title">
      <xsl:choose>
        <xsl:when test="title">
          <xsl:value-of select="title[1]"/>
        </xsl:when>
        <xsl:when test="substring(local-name(*[1]),
                                  string-length(local-name(*[1])-3) = 'info')
                        and *[1]/title">
          <xsl:value-of select="*[1]/title[1]"/>
        </xsl:when>
        <xsl:when test="refmeta/refentrytitle">
          <xsl:value-of select="refmeta/refentrytitle"/>
        </xsl:when>
        <xsl:when test="refnamediv/refname">
          <xsl:value-of select="refnamediv/refname[1]"/>
        </xsl:when>
      </xsl:choose>
    </xsl:variable>

    <xsl:message>
      <xsl:text>ID recommended on </xsl:text>
      <xsl:value-of select="local-name(.)"/>
      <xsl:if test="$title != ''">
        <xsl:text>: </xsl:text>
        <xsl:choose>
          <xsl:when test="string-length($title) &gt; 40">
            <xsl:value-of select="substring($title,1,40)"/>
            <xsl:text>...</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="$title"/>
          </xsl:otherwise>
        </xsl:choose>
      </xsl:if>
    </xsl:message>
  </xsl:if>
</xsl:template>

<xsl:template name="generate.class.attribute">
  <xsl:param name="class" select="local-name(.)"/>
  <xsl:apply-templates select="." mode="class.attribute">
    <xsl:with-param name="class" select="$class"/>
  </xsl:apply-templates>
</xsl:template>

<xsl:template match="*" mode="class.attribute">
  <xsl:param name="class" select="local-name(.)"/>
  <!-- permit customization of class attributes -->
  <!-- Use element name by default -->
  <xsl:attribute name="class">
    <xsl:apply-templates select="." mode="class.value">
      <xsl:with-param name="class" select="$class"/>
    </xsl:apply-templates>
  </xsl:attribute>
</xsl:template>

<xsl:template match="*" mode="class.value">
  <xsl:param name="class" select="local-name(.)"/>
  <!-- permit customization of class value only -->
  <!-- Use element name by default -->
  <xsl:value-of select="$class"/>
</xsl:template>

<!-- Apply common attributes such as class, lang, dir -->
<xsl:template name="common.html.attributes">
  <xsl:param name="inherit" select="0"/>
  <xsl:param name="class" select="local-name(.)"/>
  <xsl:apply-templates select="." mode="common.html.attributes">
    <xsl:with-param name="class" select="$class"/>
    <xsl:with-param name="inherit" select="$inherit"/>
  </xsl:apply-templates>
</xsl:template>

<xsl:template match="*" mode="common.html.attributes">
  <xsl:param name="class" select="local-name(.)"/>
  <xsl:param name="inherit" select="0"/>
  <xsl:call-template name="generate.html.lang"/>
  <xsl:call-template name="dir">
    <xsl:with-param name="inherit" select="$inherit"/>
  </xsl:call-template>
  <xsl:apply-templates select="." mode="class.attribute">
    <xsl:with-param name="class" select="$class"/>
  </xsl:apply-templates>
  <xsl:call-template name="generate.html.title"/>
</xsl:template>

<!-- Apply common attributes not including class -->
<xsl:template name="locale.html.attributes">
  <xsl:apply-templates select="." mode="locale.html.attributes"/>
</xsl:template>

<xsl:template match="*" mode="locale.html.attributes">
  <xsl:call-template name="generate.html.lang"/>
  <xsl:call-template name="dir"/>
  <xsl:call-template name="generate.html.title"/>
</xsl:template>

<!-- Pass through any lang attributes -->
<xsl:template name="generate.html.lang">
  <xsl:apply-templates select="." mode="html.lang.attribute"/>
</xsl:template>

<xsl:template match="*" mode="html.lang.attribute">
  <!-- match the attribute name to the output type -->
  <xsl:choose>
    <xsl:when test="@lang and $stylesheet.result.type = 'html'">
      <xsl:attribute name="lang">
        <xsl:value-of select="@lang"/>
      </xsl:attribute>
    </xsl:when>
    <xsl:when test="@lang and $stylesheet.result.type = 'xhtml'">
      <xsl:attribute name="xml:lang">
        <xsl:value-of select="@lang"/>
      </xsl:attribute>
    </xsl:when>
    <xsl:when test="@xml:lang and $stylesheet.result.type = 'html'">
      <xsl:attribute name="lang">
        <xsl:value-of select="@xml:lang"/>
      </xsl:attribute>
    </xsl:when>
    <xsl:when test="@xml:lang and $stylesheet.result.type = 'xhtml'">
      <xsl:attribute name="xml:lang">
        <xsl:value-of select="@xml:lang"/>
      </xsl:attribute>
    </xsl:when>
  </xsl:choose>
</xsl:template>

</xsl:stylesheet>

