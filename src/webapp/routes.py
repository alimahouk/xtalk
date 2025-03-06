from flask import request

from webapp import app
from webapp import xtalk


@app.route("/")
@app.route("/index")
def index():
        return """
        <!DOCTYPE html>
        <html>
                <head>
                        <title>Welcome!</title>
                </head>
                <body>
                        <h1>Welcome!</h1>
                        <form name="composer" method="post" action="/xtalk/send">
                                <table>
                                        <tr><td><input type="text" name="recipient" placeholder="Recipient" autofocus></td></tr>
                                        <tr><td><textarea name="message" placeholder="Your message…" required></textarea></td></tr>
                                        <tr><td><button type="submit">Send</button></td></tr>
                                </table>
                        </form>
                        <div>
                                <hr>
                                <dl>
                                        <dt id="ref"><dt>
                                        <dd id="status"></dd>
                                </dl>
                        </div>
                </body>
                <script type="text/javascript">
                        let form = document.composer;
                        var delivered = false;

                        form.addEventListener("submit", function(e) {
                                delivered = false;

                                document.getElementsByTagName("div")[0].removeAttribute("id");

                                let refLabel = document.getElementById("ref");
                                refLabel.innerHTML = "";

                                let statusLabel = document.getElementById("status");
                                statusLabel.innerHTML = "";

                                let data = new FormData(this);
                                var request = new XMLHttpRequest();
                                request.onreadystatechange = function() {
                                        if (this.readyState === 4 && this.status === 200) {
                                                // Get the returned message identifier to use for status polling.
                                                let parts = this.responseText.split(":");
                                                let messageId = parts[1].trim();
                                                document.getElementsByTagName("div")[0].setAttribute("id", messageId);

                                                refLabel.innerHTML = "<strong>Message ID:</strong> " + messageId;
                                                // Clear the textarea.
                                                form.message.value = ""; 
                                        }
                                };
                                request.open("POST", this.action);
                                request.send(data);

                                e.preventDefault();
                        });
                        
                        /* 
                         * The page will continually poll xTalk for the status of the message
                         * until it's delivered.
                         */
                        let statusCheck = setInterval(function() {
                                let messageId = document.getElementsByTagName("div")[0].getAttribute("id");
                                if (messageId && !delivered) {
                                        let data = new FormData();
                                        data.append("message_id", messageId);
                                        var request = new XMLHttpRequest();
                                        request.onreadystatechange = function() {
                                                if (this.readyState === 4 && this.status === 200) {
                                                        let parts = this.responseText.split(" ");
                                                        let date = parts[2];
                                                        let time = parts[3];

                                                        var status = "";
                                                        if (parts[1] == "1") {
                                                                status = "Pending";
                                                        } else if (parts[1] == "2") {
                                                                status = "Sent";
                                                        } else {
                                                                status = "Delivered";
                                                                delivered = true;
                                                        }

                                                        let statusLabel = document.getElementById("status");
                                                        statusLabel.innerHTML = "• <strong>Status:</strong> " + status + " on " + date + " at " + time;
                                                }
                                        };
                                        request.open("POST", "/xtalk/status");
                                        request.send(data);
                                }
                        }, 2000);
                </script>
        </html>
        """

@app.route("/xtalk/send", methods=["POST"])
def sendMessage():
        recipient = request.form["recipient"]
        message = request.form["message"]
        
        adapter = xtalk.Adapter()
        receipt = adapter.send(recipient, message)
        return receipt

@app.route("/xtalk/status", methods=["POST"])
def checkMessageStatus():
        messageId = request.form["message_id"]

        adapter = xtalk.Adapter()
        status = adapter.checkStatus(messageId)
        return status
