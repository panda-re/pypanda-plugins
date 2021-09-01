class BasicBlockCount(PandaPlugin):
    def __init__(self, panda):
        self.bb_count = 0

        @panda.cb_before_block_exec
        def my_before_block_fn(_cpu, _trans):
            self.bb_count += 1

    def webserver_init(self, app):
        print("Initializing web server...")

        @app.route("/bb_count")
        def bb_count():
            return str(self.bb_count)

        @app.route("/")
        def test_index():
            return """<html>
            <body>
                <p>
                    Basic Block Count: <span id="bb_count">0</span>
                </p>
                <script>
                    var bb_count = document.getElementById("bb_count");
                    setInterval(() => {
                        fetch("./bb_count")
                            .then(resp => resp.text())
                            .then(text => {
                                bb_count.innerText = text;
                            });
                    }, 200);
                </script>
            </body>
            </html>"""
