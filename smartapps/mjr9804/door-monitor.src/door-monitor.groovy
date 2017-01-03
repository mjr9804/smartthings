/**
 *  Door Monitor
 *
 *  Copyright 2016 Michael Robertson
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
/* TODO
 - Alarms - test notifications with custom lock handler
 - Test all unlock and open events
 - Close all doors
 - Lock all doors
 - Defaults?
*/
definition(
    name: "Door Monitor",
    namespace: "mjr9804",
    author: "Michael Robertson",
    description: "Monitor doors/locks and get an alert when something unexpected happens",
    category: "",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
    iconX3Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png")

preferences {
    page(name: "pageOne", title: "Monitor these things", nextPage: "pageTwo", install: false, uninstall: true) {
        section() {
            input "doors", "capability.contactSensor", title: "Doors", required: false, multiple: true
            input "locks", "capability.lock", title: "Locks", required: false, multiple: true
        }
    }
    page(name: "pageTwo", title: "Use these emergency contact methods", nextPage: "pageThree", uninstall: true) {
        section () {
            input "pushNotif", "bool", title: "Send a push notification", default: false, required: false
            input "textNotif1", "bool", title: "Send a text message to Phone #1", default: false, required: false
            input "phone1", "phone", title: "Phone #1", required: false
            input "textNotif2", "bool", title: "Send a text message to Phone #2", default: false, required: false
            input "phone2", "phone", title: "Phone #2", required: false
        }
    }
    page(name: "pageThree", title: "When I'm home...", nextPage: "pageFour", uninstall: true) {
        section("If an alarm goes off") {
            input "homeAlarmAlert", "bool", title: "Alert me", default: false, required: false
            input "homeAlarmClose", "bool", title: "Close all doors", default: false, required: false
            input "homeAlarmLock", "bool", title: "Lock all doors", default: false, required: false
        }
    }
    page(name: "pageFour", title: "When I'm away...", nextPage: "pageFive", uninstall: true) {
        section("If an alarm goes off") {
            input "awayAlarmAlert", "bool", title: "Alert me", default: true, required: false
            input "awayAlarmClose", "bool", title: "Close all doors", default: false, required: false
            input "awayAlarmLock", "bool", title: "Lock all doors", default: false, required: false
        }
        section("If a door unlocks") {
            input "awayUnlockAlert", "bool", title: "Alert me", default: true, required: false
        }
        section("If a door opens") {
            input "awayOpenAlert", "bool", title: "Alert me", default: true, required: false
        }
    }
    page(name: "pageFive", title: "When it's night...", install: true, uninstall: true) {
        section("If an alarm goes off") {
            input "nightAlarmAlert", "bool", title: "Alert me", default: true, required: false
            input "nightAlarmClose", "bool", title: "Close all doors", default: false, required: false
            input "nightAlarmLock", "bool", title: "Lock all doors", default: false, required: false
        }
        section("If a door unlocks") {
            input "nightUnlockAlert", "bool", title: "Alert me", default: true, required: false
        }
        section("If a door opens") {
            input "nightOpenAlert", "bool", title: "Alert me", default: true, required: false
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
    //subscribe(locks, "tamper", evtHandler)
	subscribe(locks, "lock", evtHandler)
    subscribe(doors, "contact", evtHandler)
}

def sendAlert(text) {
    if (pushNotif == true) {
        log.debug "Sending push notification"
        sendPush(text)
    }
    if (textNotif1 == true) {
        log.debug "Sending SMS to phone1"
        sendSms(phone1, text)
    }
    if (textNotif2 == true) {
        log.debug "Sending SMS to phone2"
        sendSms(phone2, text)
    }
}

def takeAction(event, text) {
   def currMode = location.mode
   log.debug "current mode is $currMode" // "Home", "Away", "Night"
   switch (currMode) {
       case "Home":
          break
       case "Away":
          if (event == "unlocked" && awayUnlockAlert == true) {
              sendAlert(text)
          }
          else if (event == "open" && awayOpenAlert == true) {
              sendAlert(text)
          }
          else if (event == "detected" && awayAlarmAlert == true) {
              sendAlert(text)
          }
          break
       case "Night":
          if (event == "unlocked" && nightUnlockAlert == true) {
              sendAlert(text)
          }
          else if (event == "open" && nightOpenAlert == true) {
              sendAlert(text)
          }
          else if (event == "detected" && nightAlarmAlert == true) {
              sendAlert(text)
          }
          break
   }
}

def evtHandler(evt) {
  log.debug "desc text: ${evt.descriptionText}"
  log.debug "string value: ${evt.stringValue}"
  takeAction(evt.stringValue, evt.descriptionText)
}