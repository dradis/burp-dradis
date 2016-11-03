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

      dradis_menu.add_action_listener { send_to_dradis(invocation) }
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

  # Internal: use Burp's facilities to store extension settings.
  #
  # Returns nothing.
  def save_settings
    @callbacks.save_extension_setting 'endpoint', @field_endpoint.text
    @callbacks.save_extension_setting 'token', @field_token.text
    @stdout.println 'Configuration saved.'
  end

  # Internal: get an Issue and send it to Dradis using the HTTP API.
  #
  # invocation - The IContextMenuInvocation we're receiving from Burp's menu
  #              item click.
  #
  # Returns nothing.
  #
  def send_to_dradis(invocation)

    endpoint = @field_endpoint.text

    payload = {
      issue: {
        text: 'Lorem ipsum Burp...'
      }
    }.to_json

    token = @field_token.text

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

  # Internal: use Burp's facilities to restore extension settings.
  #
  # Returns nothing.
  def restore_settings
    @field_endpoint.text = @callbacks.load_extension_setting('endpoint')
    @field_token.text    = @callbacks.load_extension_setting('token')
    @stdout.println 'Configuration restored.'
  end

end
