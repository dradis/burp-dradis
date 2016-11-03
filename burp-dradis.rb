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
require 'uri'

java_import 'javax.swing.GroupLayout'
java_import 'javax.swing.JMenuItem'
java_import 'javax.swing.JPanel'

java_import 'burp.IBurpExtender'
java_import 'burp.IExtensionHelpers'
java_import 'burp.IContextMenuFactory'
java_import 'burp.IContextMenuInvocation'
java_import 'burp.ITab'


class BurpExtender
  include IBurpExtender, IContextMenuFactory, ITab

  VERSION = '0.0.1'


  # ------------------------------------------------------------- IBurpExtender
  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks

    # set our extension name
    callbacks.setExtensionName('Dradis Framework connector')

    # obtain a reference to the helpers
    @helpers = callbacks.getHelpers()

    # obtain our output and error streams
    @stdout = java.io.PrintWriter.new(callbacks.getStdout(), true)
    @stderr = java.io.PrintWriter.new(callbacks.getStderr(), true)

    @stdout.println "Loading Dradis Framework extension (v#{VERSION})..."

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

    @stdout.println( "menu: #{invocation.invocation_context} | #{IContextMenuInvocation::CONTEXT_SCANNER_RESULTS}")

    menu
  end
  # ------------------------------------------------------ /IContextMenuFactory

  # ---------------------------------------------------------------------- ITab
  def getTabCaption
    'Dradis Framework'
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
    layout       = javax.swing.GroupLayout.new(panel)
    panel.setLayout(layout)

    layout.setAutoCreateGaps(true)
    layout.setAutoCreateContainerGaps(true)


    @field_endpoint = javax.swing.JTextField.new()
    label_endpoint  = javax.swing.JLabel.new('Dradis URL')
    label_endpoint.setLabelFor(@field_endpoint)


    @field_token = javax.swing.JTextField.new()
    label_token  = javax.swing.JLabel.new('API token')
    label_token.setLabelFor(@field_token)

    button_save = javax.swing.JButton.new('Save')
    button_save.add_action_listener { save_settings }


    layout.setHorizontalGroup(
      layout.createSequentialGroup()
        .addGroup(layout.createParallelGroup()
          .addComponent(label_endpoint)
          .addComponent(label_token)
        )
        .addGroup(layout.createParallelGroup()
          .addComponent(@field_endpoint)
          .addComponent(@field_token)
          .addComponent(button_save)
        )
    )

    layout.setVerticalGroup(
      layout.createSequentialGroup()
        .addGroup(layout.createParallelGroup()
          .addComponent(label_endpoint)
          .addComponent(@field_endpoint)
        )
        .addGroup(layout.createParallelGroup()
          .addComponent(label_token)
          .addComponent(@field_token)
        )
        .addGroup(layout.createParallelGroup()
          .addComponent(button_save)
        )
    )

    panel
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
    issue_text.sub!(/%issue\.background%/, issue.issue_background)
    issue_text.sub!(/%issue\.remediation_background%/, issue.remediation_background)
    issue_text.sub!(/%issue\.detail%/, issue.issue_detail)
    issue_text.sub!(/%issue\.remediation_detail%/, issue.remediation_detail)

    { issue: { text: issue_text } }.to_json
  end

  # Internal: get an Issue and send it to Dradis using the HTTP API.
  #
  # issue - The IScanIssue we're receiving from Burp's menu item click.
  #
  # Returns nothing.
  #
  def create_dradis_issue(issue)
    endpoint = @field_endpoint.text
    token    = @field_token.text
    payload  = build_json_payload(issue)

    begin
      uri      = URI.parse(endpoint)
      http     = Net::HTTP.new(uri.host, uri.port)
      request  = Net::HTTP::Post.new('/api/issues')

      request['Content-Type'] = 'application/json'
      request.basic_auth('BurpExtender', token)
      request.body = payload


      @stdout.print "Sending POST to #{endpoint}#{request.path}... "
      response = http.request(request)
      @stdout.println "#{response.code} #{response.message}."
    rescue Exception => e
      @callbacks.issue_alert("There was an error connecting to Dradis: #{e.message}")
      @stderr.println e.backtrace
    end
  end

  # Internal: use Burp's facilities to store extension settings.
  #
  # Returns nothing.
  def save_settings
    @callbacks.save_extension_setting 'endpoint', @field_endpoint.text
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

  # Internal: use Burp's facilities to restore extension settings.
  #
  # Returns nothing.
  def restore_settings
    @field_endpoint.text = @callbacks.load_extension_setting('endpoint')
    @field_token.text    = @callbacks.load_extension_setting('token')
    @stdout.println 'Configuration restored.'
  end

end
