/**
 *  Extended Routines
 *
 *  Copyright 2017 Michael Robertson
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 */
definition(
    name: "Extended Routines",
    namespace: "mjr9804",
    author: "Michael Robertson",
    description: "Runs a custom set of actions, followed by an automation routine.",
    category: "",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
    iconX3Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png")


preferences {
    page(name: "pageOne", title: "Extended Actions", nextPage: "selectActions", install: false, uninstall: true) {
        section("Alarms") {
            input "alarmMode", "enum", title: "Set alarm mode to...", options: ["0": "Disabled", "1": "Alert", "2": "Tamper", "3": "Kick"], required: false
            input "locks", "capability.lock", title: "On these devices...", required: false, multiple: true
        }
    }
    page(name: "selectActions")
}

def selectActions() {
    dynamicPage(name: "selectActions", title: "Select Hello Home Action to Execute", install: true, uninstall: true) {    
        def actions = location.helloHome?.getPhrases()*.label
        if (actions) {
            actions.sort()
            section() {
                // note: this doesn't work in the IDE simulator, it stores the index instead of the routine name
                input "routine", "enum", title: "Then run this routine...", options: actions
                input "runTime", "time", title: "Every day at..."
            }
        }
    }
}

def installed() {
	log.debug "Installed with settings: ${settings}"

	initialize()
}

def updated() {
	log.debug "Updated with settings: ${settings}"

	unsubscribe()
	initialize()
}

def initialize() {
    schedule(runTime, handler)
}

def handler() {
    if (alarmMode && locks) {
        setAlarms()
    }
    def actions = location.helloHome?.getPhrases()*.label
    log.debug "Executing "+settings.routine
    location.helloHome?.execute(settings.routine)
}

def setAlarms() {
    for (lock in locks) {
        lock.setAlarmMode(alarmMode)    
    }
}