        document.addEventListener('readystatechange', event => { 
        // When HTML/DOM elements are ready -->
        //if (event.target.readyState === "interactive") {   //does same as:  ..addEventListener("DOMContentLoaded"..
        //}

        // When window loaded ( external resources are loaded too ) 
        if (event.target.readyState === "complete") {
          cvc.setUser(useremail, useremail)
          cvc.setCad({"idtoken":idtoken})
          cvc.attachEvent("ready  ", function () {alert(JSON.stringify(this.event)), ""});
          cvc.attachEvent("completed", function () {alert(JSON.stringify(this.event)), ""});
          cvc.attachEvent("ended", function () {alert(JSON.stringify(this.event)), ""});         
         
        }
      });
