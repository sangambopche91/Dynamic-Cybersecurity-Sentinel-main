
class ResponseEngine:
    """
    Generates defensive response recommendations based on
    attack type and severity.

    Attack type determines WHAT defensive action is appropriate.
    Severity determines HOW urgently the action should be taken.

    This module provides recommendations only.
    It does not execute firewall, blocking, or system commands.
    """

    def __init__(self):

        # ==================================================
        # Attack Type + Severity Response Matrix
        # ==================================================

        self.responses = {

            # --------------------------------------------------
            # DoS
            # --------------------------------------------------

            "DoS": {

                "Low": [
                    "Monitor traffic volume and connection rates.",
                    "Continue observing the suspected source."
                ],

                "Medium": [
                    "Investigate the suspected traffic source.",
                    "Monitor bandwidth and connection saturation.",
                    "Review network logs for continued activity."
                ],

                "High": [
                    "Apply traffic filtering or rate limiting.",
                    "Monitor service availability and bandwidth usage.",
                    "Investigate and monitor suspicious traffic sources.",
                    "Review network logs for continued disruption."
                ],

                "Critical": [
                    "Immediately apply traffic filtering or rate limiting.",
                    "Block suspicious source traffic where appropriate.",
                    "Monitor service availability and network saturation.",
                    "Preserve relevant network evidence and logs.",
                    "Escalate the incident to the security administrator."
                ]
            },


            # --------------------------------------------------
            # Exploits
            # --------------------------------------------------

            "Exploits": {

                "Low": [
                    "Review the targeted service for suspicious activity.",
                    "Continue monitoring application and system logs."
                ],

                "Medium": [
                    "Investigate the targeted service or application.",
                    "Review application and system logs.",
                    "Check for early indicators of exploitation."
                ],

                "High": [
                    "Investigate the targeted service immediately.",
                    "Check for indicators of successful exploitation.",
                    "Review application and system logs.",
                    "Consider isolating the affected system if compromise is suspected."
                ],

                "Critical": [
                    "Immediately investigate the targeted service.",
                    "Check for successful exploitation and compromise indicators.",
                    "Isolate the affected system if compromise is suspected.",
                    "Preserve application, system, and network evidence.",
                    "Escalate the incident to the security administrator."
                ]
            },


            # --------------------------------------------------
            # Fuzzers
            # --------------------------------------------------

            "Fuzzers": {

                "Low": [
                    "Monitor unusual or malformed network requests.",
                    "Continue normal application monitoring."
                ],

                "Medium": [
                    "Inspect malformed or unusual network requests.",
                    "Review application and service logs.",
                    "Monitor the targeted service for repeated probing."
                ],

                "High": [
                    "Investigate repeated malformed requests.",
                    "Review the targeted application's logs.",
                    "Monitor the service for exploitation attempts.",
                    "Investigate the suspected source."
                ],

                "Critical": [
                    "Immediately investigate the targeted application.",
                    "Check for exploitation or service compromise.",
                    "Restrict suspicious traffic where appropriate.",
                    "Preserve application and network logs.",
                    "Escalate the incident if compromise is suspected."
                ]
            },


            # --------------------------------------------------
            # Reconnaissance
            # --------------------------------------------------

            "Reconnaissance": {

                "Low": [
                    "Monitor the suspected source for continued scanning.",
                    "Review unusual connection attempts."
                ],

                "Medium": [
                    "Monitor the suspected source for scanning activity.",
                    "Review connection attempts and discovery patterns.",
                    "Inspect exposed network services."
                ],

                "High": [
                    "Investigate the scanning source and activity.",
                    "Review targeted services and connection patterns.",
                    "Monitor for continued reconnaissance attempts.",
                    "Restrict suspicious scanning traffic where appropriate."
                ],

                "Critical": [
                    "Immediately investigate the reconnaissance source.",
                    "Restrict or block suspicious scanning traffic where appropriate.",
                    "Review exposed services and potential attack targets.",
                    "Monitor for follow-up exploitation attempts.",
                    "Escalate the incident for further investigation."
                ]
            },


            # --------------------------------------------------
            # Backdoor
            # --------------------------------------------------

            "Backdoor": {

                "Low": [
                    "Monitor suspicious external communication.",
                    "Review authentication and system logs."
                ],

                "Medium": [
                    "Investigate suspicious external communication.",
                    "Inspect active processes on the affected host.",
                    "Review authentication and system logs."
                ],

                "High": [
                    "Investigate suspicious external communication immediately.",
                    "Inspect active processes and persistence mechanisms.",
                    "Review authentication and system logs.",
                    "Consider isolating the affected system."
                ],

                "Critical": [
                    "Immediately isolate the affected system.",
                    "Block suspicious external communication where appropriate.",
                    "Inspect processes and persistence mechanisms.",
                    "Preserve system and network forensic evidence.",
                    "Escalate for malware and compromise investigation."
                ]
            },


            # --------------------------------------------------
            # Shellcode
            # --------------------------------------------------

            "Shellcode": {

                "Low": [
                    "Monitor the affected process.",
                    "Review relevant application logs."
                ],

                "Medium": [
                    "Investigate the affected process.",
                    "Review system and application logs.",
                    "Check for exploitation indicators."
                ],

                "High": [
                    "Investigate the affected process immediately.",
                    "Check for successful exploitation indicators.",
                    "Inspect suspicious process or memory activity.",
                    "Consider isolating the affected system."
                ],

                "Critical": [
                    "Immediately isolate the affected system.",
                    "Investigate the affected process and memory activity.",
                    "Check for successful exploitation and compromise.",
                    "Preserve forensic evidence and system logs.",
                    "Escalate for exploitation investigation."
                ]
            },


            # --------------------------------------------------
            # Worms
            # --------------------------------------------------

            "Worms": {

                "Low": [
                    "Monitor the affected host for propagation activity.",
                    "Review unusual network connections."
                ],

                "Medium": [
                    "Monitor the affected host for propagation.",
                    "Review network and system logs.",
                    "Check nearby systems for similar activity."
                ],

                "High": [
                    "Restrict suspicious lateral network communication.",
                    "Check connected systems for similar activity.",
                    "Investigate the suspected propagation path.",
                    "Review network and system logs."
                ],

                "Critical": [
                    "Immediately isolate the affected system.",
                    "Restrict lateral network communication.",
                    "Check connected systems for signs of propagation.",
                    "Preserve network and system evidence.",
                    "Escalate as a potential malware propagation incident."
                ]
            },


            # --------------------------------------------------
            # Generic
            # --------------------------------------------------

            "Generic": {

                "Low": [
                    "Monitor the detected network activity.",
                    "Continue normal security monitoring."
                ],

                "Medium": [
                    "Investigate the detected network activity.",
                    "Review protocol and application behavior.",
                    "Monitor the suspected source and destination."
                ],

                "High": [
                    "Investigate the detected activity immediately.",
                    "Review protocol and application behavior.",
                    "Monitor the suspected source and destination.",
                    "Review relevant security logs."
                ],

                "Critical": [
                    "Immediately investigate the detected network activity.",
                    "Restrict suspicious traffic where appropriate.",
                    "Review protocol and application behavior for compromise indicators.",
                    "Preserve relevant network and system evidence.",
                    "Escalate the incident for further investigation."
                ]
            },


            # --------------------------------------------------
            # Analysis
            # --------------------------------------------------

            "Analysis": {

                "Low": [
                    "Monitor unusual probing or analysis activity.",
                    "Review relevant network traffic."
                ],

                "Medium": [
                    "Investigate unusual probing or analysis activity.",
                    "Review connection patterns and targeted services.",
                    "Monitor the suspected source."
                ],

                "High": [
                    "Investigate the analysis activity and suspected source.",
                    "Review targeted services and connection patterns.",
                    "Monitor for continued probing.",
                    "Review relevant network and security logs."
                ],

                "Critical": [
                    "Immediately investigate the suspected source.",
                    "Restrict suspicious probing activity where appropriate.",
                    "Review targeted services for possible attack preparation.",
                    "Monitor for follow-up exploitation attempts.",
                    "Escalate the incident for further investigation."
                ]
            },


            # --------------------------------------------------
            # Unknown Anomaly
            # --------------------------------------------------

            "Unknown Anomaly": {

                "Low": [
                    "Continue monitoring the anomalous network activity.",
                    "Review the affected traffic if the activity continues."
                ],

                "Medium": [
                    "Investigate the anomalous network activity.",
                    "Review the affected traffic and related network flows.",
                    "Monitor the suspected source and destination."
                ],

                "High": [
                    "Investigate the anomalous activity immediately.",
                    "Review related network flows and communication patterns.",
                    "Monitor the suspected source and destination.",
                    "Preserve relevant logs for further investigation."
                ],

                "Critical": [
                    "Immediately investigate the anomalous activity.",
                    "Restrict suspicious traffic where appropriate.",
                    "Review related network and system activity for compromise.",
                    "Preserve relevant logs and forensic evidence.",
                    "Escalate the incident as a potentially unknown threat."
                ]
            },


            # --------------------------------------------------
            # Normal
            # --------------------------------------------------

            "Normal": {

                "Low": [
                    "Continue normal security monitoring."
                ],

                "Medium": [
                    "Continue normal security monitoring."
                ],

                "High": [
                    "Review the event because the detected severity is inconsistent with normal classification."
                ],

                "Critical": [
                    "Immediately investigate the event because the detected severity is inconsistent with normal classification.",
                    "Preserve relevant logs for further investigation.",
                    "Escalate the event to the security administrator."
                ]
            }
        }


    # ==================================================
    # Get Response
    # ==================================================

    def get_response(self, attack_type, severity):

        attack_type = str(attack_type)
        severity = str(severity)

        # --------------------------------------------------
        # Unknown attack type
        # --------------------------------------------------

        if attack_type not in self.responses:

            attack_type = "Unknown Anomaly"

        # --------------------------------------------------
        # Unknown severity
        # --------------------------------------------------

        if severity not in [
            "Low",
            "Medium",
            "High",
            "Critical"
        ]:

            severity = "Medium"

        # --------------------------------------------------
        # Return attack + severity specific response
        # --------------------------------------------------

        return self.responses[
            attack_type
        ][
            severity
        ]


# ==================================================
# Direct Test
# ==================================================

if __name__ == "__main__":

    engine = ResponseEngine()

    print("=" * 70)
    print("DYNAMIC CYBERSECURITY SENTINEL")
    print("ATTACK TYPE + SEVERITY RESPONSE ENGINE TEST")
    print("=" * 70)


    test_cases = [

        ("DoS", "Low"),
        ("DoS", "Medium"),
        ("DoS", "High"),
        ("DoS", "Critical"),

        ("Exploits", "High"),
        ("Backdoor", "Critical"),
        ("Fuzzers", "Medium"),
        ("Reconnaissance", "High"),
        ("Shellcode", "Critical"),
        ("Worms", "Critical"),
        ("Unknown Anomaly", "Medium"),
        ("Normal", "Low")
    ]


    for attack_type, severity in test_cases:

        print("\n" + "-" * 70)

        print("Attack Type :", attack_type)
        print("Severity    :", severity)

        print("Recommended Response:")

        responses = engine.get_response(
            attack_type,
            severity
        )

        for response in responses:

            print("-", response)


    print("\n" + "=" * 70)
