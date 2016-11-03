# Dradis Framework extension for Burp Suite

This extension allows users to send issues from Burp's Scanner directly into their Dradis project using the HTTP API.


## Dependencies

This extension is written in Ruby, you will need a JRuby Complete package from http://www.jruby.org/download.

To load the ruby interpreter in burp, go to Extender->Options, and in the Ruby Environment section set the PATH of the jruby-complete.jar file.

![Burp > Options > Ruby Environment](https://camo.githubusercontent.com/afc119e6cff722337e576629f8ee2a4e399f9686/68747470733a2f2f7261772e6769746875622e636f6d2f77696b692f696e666f627974652f666172616461792f696d616765732f627572705f727562795f706174682e706e67)


## Install

### Normal use

Extender > BApp Store and activate the Dradis Framework Connector.

### Development

Extender > Extensions > Add:

* Extension type: `Ruby`
* Extension file (.rb): `burp-dradis.rb`


## Contributing

Please see CONTRIBUTING.md for details.

List of [contributors](https://github.com/dradis/burp-dradis/graphs/contributors).


## License

The Dradis Framework extension for Burp is released under [GNU General Public License version 2.0](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
