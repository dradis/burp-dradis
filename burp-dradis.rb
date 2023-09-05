#!/usr/bin/env ruby
#
# This Burp Suite extension allows you to post information into your Dradis
# Framework instance directly from within Burp Suite. The extension uses Dradis'
# REST HTTP API.
#
# Dradis Framework is a collaboration and reporting tool for InoSec
# professionals that lets you combine the output of different security scanners
# and your own manual findings and screenshots into a single custom report.
# Read more at:
#
#   http://dradisframework.org
#
# Canonical source for this code:
#
#   http://github.com/dradis/burp-dradis/
#
# Copyright (c) 2016, Daniel Martin <etd[at]nomejortu.com>
# All rights reserved.
#
# Licensed under GPLv2. See LICENSE.txt for full licensing information.
#

require 'java'
require 'json'
require 'net/http'
require 'openssl'
require 'uri'

java_import 'java.awt.BorderLayout'
java_import 'java.awt.Color'
java_import 'java.awt.Desktop'
java_import 'java.awt.GridBagConstraints'
java_import 'java.awt.GridBagLayout'
java_import 'java.awt.Toolkit'
java_import 'java.awt.datatransfer.StringSelection'
java_import 'javax.swing.BorderFactory'
java_import 'javax.swing.Box'
java_import 'javax.swing.ButtonGroup'
java_import 'javax.swing.GroupLayout'
java_import 'javax.swing.JCheckBox'
java_import 'javax.swing.JEditorPane'
java_import 'javax.swing.JMenuItem'
java_import 'javax.swing.JOptionPane'
java_import 'javax.swing.JPanel'
java_import 'javax.swing.JRadioButton'
java_import 'javax.swing.JSeparator'
java_import 'javax.swing.SwingConstants'
java_import 'javax.swing.event.HyperlinkEvent'
java_import 'javax.swing.event.HyperlinkListener'

java_import 'burp.IBurpExtender'
java_import 'burp.IContextMenuFactory'
java_import 'burp.IContextMenuInvocation'
java_import 'burp.IExtensionHelpers'
java_import 'burp.ITab'


class BurpExtender
  include HyperlinkListener, IBurpExtender, IContextMenuFactory, ITab

  module META
    NAME        = 'Dradis Framework connector'
    TAB_CAPTION = 'Dradis Framework'
    VERSION     = '0.0.4'
  end


  # ------------------------------------------------------------- IBurpExtender
  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks

    # set our extension name
    callbacks.setExtensionName(META::NAME)

    # obtain a reference to the helpers
    @helpers = callbacks.getHelpers()

    # obtain our output and error streams
    @stdout = java.io.PrintWriter.new(callbacks.getStdout(), true)
    @stderr = java.io.PrintWriter.new(callbacks.getStderr(), true)

    @stdout.println "Loading #{META::NAME} (v#{META::VERSION})..."

    # Register a factory for custom context menu items
    callbacks.registerContextMenuFactory(self)

    # Add a configuration tab
    callbacks.addSuiteTab(self)

    # Restore settings
    restore_settings()
  end
  # ------------------------------------------------------------ /IBurpExtender


  # ------------------------------------------------------- IContextMenuFactory
  def createMenuItems(invocation)
    menu = []

    case invocation.invocation_context
    when IContextMenuInvocation::CONTEXT_SCANNER_RESULTS, IContextMenuInvocation::CONTEXT_INTRUDER_PAYLOAD_POSITIONS
      dradis_menu = JMenuItem.new('Send to Dradis', nil)

      dradis_menu.add_action_listener { send_to_dradis_menu_handler(invocation) }
      menu << dradis_menu
    end

    menu
  end
  # ------------------------------------------------------ /IContextMenuFactory

  # ---------------------------------------------------------------------- ITab
  def getTabCaption
    META::TAB_CAPTION
  end

  def getUiComponent
    @tab ||= build_config_panel()
  end
  # --------------------------------------------------------------------- /ITab


  private

  # Internal: build a Java SWING JPanel to keep all of our config options.
  #
  # Returns the JPanel component.
  #
  def build_config_panel
    panel        = javax.swing.JPanel.new
    layout       = java.awt.GridBagLayout.new
    constraints  = java.awt.GridBagConstraints.new

    panel.setLayout(layout)
    panel.setBorder( BorderFactory.createEtchedBorder() )

    label_title            = javax.swing.JLabel.new('<html><h3>Dradis Framework connector configuration</h3></html>')
    label_title.foreground = java.awt.Color.new(209,122,33)

    label_description = javax.swing.JLabel.new('Use this connector to send Burp Scanner issues to your Dradis Framework instance.')

    label_edition = javax.swing.JLabel.new('Edition:')

    @radio_ce = javax.swing.JRadioButton.new('')
    @radio_ce.addActionListener { toggle_edition() }
    @radio_ce.selected = true

    @radio_pro = javax.swing.JRadioButton.new('')
    @radio_pro.addActionListener { toggle_edition() }

    @edition_group = javax.swing.ButtonGroup.new()
    @edition_group.add(@radio_ce)
    @edition_group.add(@radio_pro)

    editor_ce            = javax.swing.JEditorPane.new(
                             'text/html',
                             '<a href="http://dradisframework.org/?utm_source=burp&utm_medium=extension&utm_campaign=configuration">Dradis Community</a>'
                           )
    editor_ce.editable   = false
    editor_ce.opaque     = false
    editor_ce.background = java.awt.Color.new(0,0,0,0)
    editor_ce.addHyperlinkListener(self)

    editor_pro            = javax.swing.JEditorPane.new(
                              'text/html',
                              '<a href="http://securityroots.com/dradispro/editions.html?utm_source=burp&utm_medium=extension&utm_campaign=configuration">Dradis Professional</a>'
                            )
    editor_pro.editable   = false
    editor_pro.opaque     = false
    editor_pro.background = java.awt.Color.new(0,0,0,0)
    editor_pro.addHyperlinkListener(self)

    @field_endpoint = javax.swing.JTextField.new()
    label_endpoint  = javax.swing.JLabel.new('Dradis URL:')
    label_endpoint.setLabelFor(@field_endpoint)

    @field_token = javax.swing.JTextField.new()
    label_token  = javax.swing.JLabel.new('API token:')
    label_token.setLabelFor(@field_token)

    @field_project_id = javax.swing.JTextField.new()
    @field_project_id.enabled = false

    @label_project_id = javax.swing.JLabel.new('Project ID:')
    @label_project_id.setLabelFor(@field_project_id)
    @label_project_id.enabled = false

    @field_path = javax.swing.JTextField.new()
    @field_path.enabled = false
    @field_path.text = '/pro'

    @label_path = javax.swing.JLabel.new('Path:')
    @label_path.setLabelFor(@field_path)
    @label_path.enabled = false

    button_save = javax.swing.JButton.new('Save')
    button_save.add_action_listener { save_settings }

    vertical_glue = Box.createVerticalGlue()

    constraints.anchor     = java.awt.GridBagConstraints::NORTH
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.gridx      = 0
    constraints.gridy      = 0
    constraints.gridwidth  = 6
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,0,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(label_title, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::NORTH
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.gridx      = 0
    constraints.gridy      = 1
    constraints.gridwidth  = 6
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(0,10,10,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(label_description, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::EAST
    constraints.fill       = java.awt.GridBagConstraints::VERTICAL
    constraints.gridx      = 0
    constraints.gridy      = 2
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(label_edition, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::NORTH
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.gridx      = 1
    constraints.gridy      = 2
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,0)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(@radio_ce, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::WEST
    constraints.fill       = java.awt.GridBagConstraints::VERTICAL
    constraints.gridx      = 2
    constraints.gridy      = 2
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,0,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(editor_ce, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::NORTH
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.gridx      = 3
    constraints.gridy      = 2
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,0)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(@radio_pro, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::WEST
    constraints.fill       = java.awt.GridBagConstraints::VERTICAL
    constraints.gridx      = 4
    constraints.gridy      = 2
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,0,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(editor_pro, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::EAST
    constraints.fill       = java.awt.GridBagConstraints::VERTICAL
    constraints.gridx      = 0
    constraints.gridy      = 3
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(label_endpoint, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::NORTH
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.gridx      = 1
    constraints.gridy      = 3
    constraints.gridwidth  = 4
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,5)
    constraints.weightx    = 1
    constraints.weighty    = 0
    panel.add(@field_endpoint, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::EAST
    constraints.fill       = java.awt.GridBagConstraints::VERTICAL
    constraints.gridx      = 0
    constraints.gridy      = 4
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(label_token, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::NORTH
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.gridx      = 1
    constraints.gridy      = 4
    constraints.gridwidth  = 4
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(@field_token, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::EAST
    constraints.fill       = java.awt.GridBagConstraints::VERTICAL
    constraints.gridx      = 0
    constraints.gridy      = 6
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(@label_project_id, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::NORTH
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.gridx      = 1
    constraints.gridy      = 6
    constraints.gridwidth  = 4
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(@field_project_id, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::EAST
    constraints.fill       = java.awt.GridBagConstraints::VERTICAL
    constraints.gridx      = 0
    constraints.gridy      = 7
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(@label_path, constraints)

    constraints.anchor     = java.awt.GridBagConstraints::NORTH
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.gridx      = 1
    constraints.gridy      = 7
    constraints.gridwidth  = 4
    constraints.gridheight = 1
    constraints.insets     = java.awt.Insets.new(5,10,5,5)
    constraints.weightx    = 0
    constraints.weighty    = 0
    panel.add(@field_path, constraints)

    constraints.anchor  = java.awt.GridBagConstraints::WEST
    constraints.fill    = java.awt.GridBagConstraints::VERTICAL
    constraints.gridx   = 1
    constraints.gridy   = 8
    constraints.insets  = java.awt.Insets.new(5,10,5,5)
    constraints.weightx = 0
    constraints.weighty = 0
    panel.add(button_save, constraints)


    # Now we put the panel on a BorderLayout and add some vertical glue under
    # it so it remains at the top of the tab.
    container = javax.swing.JPanel.new
    container.setLayout(java.awt.BorderLayout.new(5,5))
    container.add(panel, java.awt.BorderLayout::PAGE_START)
    container.add(vertical_glue, java.awt.BorderLayout::LINE_END)
    container
  end

  # Internal: builds a an HTTP POST request with headers containing
  # authentication and payload.
  #
  # uri     - The URI that we'll use to build the request's Host and path.
  # token   - The configured Dradis API token (Pro) or shared password (CE).
  # payload - The HTTP request body to be sent
  #
  # Returns a string containing a valid HTTP POST require request.
  #
  def build_http_request(uri, token, payload)
    host = uri.host
    path = uri.path

    path << @field_path.text || '' if @radio_pro.selected
    path << '/' unless path[-1,1] == '/'
    path << 'api/issues'

    request = []
    request << "POST #{path} HTTP/1.1"
    request << "Host: #{host}"
    request << 'Accept: */*'
    request << "Content-Type: application/json"
    request << "Content-Length: #{payload.bytesize}"

    if @radio_pro.selected
      request << "Authorization: Token token=\"#{token}\""
      request << "Dradis-Project-Id: #{@field_project_id.text}"
    else
      basic = ["BurpExtender:#{token}"].pack('m').delete("\r\n")
      request << "Authorization: Basic #{basic}"
    end

    request << ""
    request << payload
    request.join("\r\n")
  end

  # Internal: this method creates a Hash we can use in the HTTP POST request to
  # create a Dradis Issue from an instance of Burp's IScanIssue.
  #
  # issue - The IScanIssue object from Burp.
  #
  # Returns a String containing the JSON format Dradis' API is expecting.
  #
  def build_json_payload(issue)
    template = "#[Title]#\n%issue.name%\n\n\n"
    template << "#[Confidence]#\n%issue.confidence%\n\n\n"
    template << "#[Severity]#\n%issue.severity%\n\n\n"
    template << "#[Background]#\n%issue.background%\n\n\n"
    template << "#[RemediationBackground]#\n%issue.remediation_background%\n\n\n"
    template << "#[Detail]#\n%issue.detail%\n\n\n"
    template << "#[RemediationDetails]#\n%issue.remediation_detail%\n\n\n"

    issue_text = template
    issue_text.sub!(/%issue\.name%/, issue.issue_name)
    issue_text.sub!(/%issue\.confidence%/, issue.confidence)
    issue_text.sub!(/%issue\.severity%/, issue.severity)
    issue_text.sub!(/%issue\.background%/, clean_markup(issue.issue_background))
    issue_text.sub!(/%issue\.remediation_background%/, clean_markup(issue.remediation_background || 'n/a'))
    issue_text.sub!(/%issue\.detail%/, clean_markup(issue.issue_detail || 'n/a'))
    issue_text.sub!(/%issue\.remediation_detail%/, clean_markup(issue.remediation_detail || 'n/a'))

    { issue: { text: issue_text } }.to_json
  end

  # Internal: cleans the Burp IScanIssue fields of HTML markup.
  #
  # field - The String containing <p> and </p> tags.
  #
  # Returns field where <p> and </p> have been stripped.
  #
  def clean_markup(field='')
    field.gsub(/<p>/i, '').gsub(/<\/p>/i, "\r\n\r\n")
  end

  # Internal: get an Issue and send it to Dradis using the HTTP API.
  #
  # issue - The IScanIssue we're receiving from Burp's menu item click.
  #
  # Returns nothing.
  #
  def create_dradis_issue(issue)
    endpoint = @field_endpoint.text || ''
    token    = @field_token.text    || ''
    payload  = build_json_payload(issue)

    unless endpoint.length > 0 && token.length > 0
      javax.swing.JOptionPane.showMessageDialog(nil, "Please configure the extension using the #{META::TAB_CAPTION} tab.")
      return
    end

    uri     = URI.parse(endpoint)
    request = build_http_request(uri, token, payload)

    begin
      send_http_request(uri, request)
    rescue Exception => e
      @callbacks.issue_alert("There was an error connecting to Dradis: #{e.message}.")
      @stderr.println e.backtrace
    end
  end

  # Internal: implementation of the HyperlinkListener interface that detects
  # clicks on UI components that have an HTML link and opens them in a browser.
  #
  # event - The HyperlinkEvent passed by Swing.
  #
  # Returns nothing.
  #
  def hyperlinkUpdate(event)
    url = event.getURL().toURI()

    return unless event.event_type == HyperlinkEvent::EventType::ACTIVATED

    # Launching a browser may not be supported in all platforms.
    if java.awt.Desktop.isDesktopSupported()
      desktop = java.awt.Desktop.getDesktop()
      desktop.browse(url)
    else
      # Copy URL to clipboard...
      contents  = java.awt.datatransfer.StringSelection.new(url.toString())
      clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
      clipboard.setContents(contents, nil)

      # ...and notify the user.
      javax.swing.JOptionPane.showMessageDialog(nil, "Couldn't launch browser so we've copied the URL to your clipboard!")
    end
  end

  # Internal: use Burp's facilities to store extension settings.
  #
  # Returns nothing.
  def save_settings
    @callbacks.save_extension_setting 'edition', @radio_ce.selected ? 'ce' : 'pro'
    @callbacks.save_extension_setting 'endpoint', @field_endpoint.text
    @callbacks.save_extension_setting 'path', @field_path.text
    @callbacks.save_extension_setting 'project_id', @field_project_id.text
    @callbacks.save_extension_setting 'token', @field_token.text

    @stdout.println 'Configuration saved.'
  end

  # Internal: context menu handler that gets a list of selected issues in the
  # Scanner window and sends them to Dradis via #create_dradis_issue.
  #
  # invocation - The IContextMenuInvocation we're receiving from Burp's menu
  #              item click.
  #
  # Returns nothing.
  #
  def send_to_dradis_menu_handler(invocation)

    if invocation.invocation_context == IContextMenuInvocation::CONTEXT_SCANNER_RESULTS
      invocation.selected_issues.each do |issue|
        create_dradis_issue(issue)
      end
    else
      issue = Struct.new(:issue_name, :confidence, :severity,
      :issue_background, :remediation_background, :issue_detail,
      :remediation_detail).new(
        'My test Issue',
        'High',
        'Low',
        'n/a/b',
        'n/a/rb',
        'n/a/d',
        'n/a/rd'
      )
      create_dradis_issue(issue)
    end
  end


  # Internal: Open a Java thread and send the request through the wire using
  # Burp's standard API for http messaging. We need a thread because Burp
  # doesn't like in-line requests that could freeze the UI.
  #
  # uri     - An URI object so we know where to send the request to
  # request - The HTTP request message we want to send to the server.
  #
  # Returns nothing.
  #
  def send_http_request(uri, request)
    host    = uri.host
    port    = uri.port
    use_ssl = uri.scheme == 'https'

    thread = java.lang.Thread.new(
      Proc.new {
        @stdout.println request

        response = @callbacks.make_http_request(host, port, use_ssl, request.to_java_bytes)
        @stdout.println(response)
        javax.swing.JOptionPane.showMessageDialog(nil, "Issue sent")
      }
    )
    thread.start
  end

  # Internal: use Burp's facilities to restore extension settings.
  #
  # Returns nothing.
  def restore_settings
    edition                = @callbacks.load_extension_setting('edition')
    @field_endpoint.text   = @callbacks.load_extension_setting('endpoint')
    ignore_ssl_errors      = @callbacks.load_extension_setting('ignore_ssl_errors')
    @field_path.text       = @callbacks.load_extension_setting('path')
    @field_project_id.text = @callbacks.load_extension_setting('project_id')
    @field_token.text      = @callbacks.load_extension_setting('token')

    edition == 'ce' ? @radio_ce.selected = true : @radio_pro.selected = true
    toggle_edition()

    @stdout.println 'Configuration restored.'
  end

  # Internal: when the user select the Dradis edition they want to work with
  # some of the config fields may need to be enabled/disabled.
  #
  # Returns nothing.
  def toggle_edition()
    if @radio_ce.selected
      @label_project_id.enabled = false
      @field_project_id.enabled = false
      @label_path.enabled       = false
      @field_path.enabled       = false
    else
      @label_project_id.enabled = true
      @field_project_id.enabled = true
      @label_path.enabled       = true
      @field_path.enabled       = true
    end
  end
end
