// Page-level behavioral collector for session tracking.
// Injected as inline script into HTML responses when a valid challenge cookie
// is present. Tracks visible dwell time, scroll depth, and interaction events.
// Beacons data on visibilitychange→hidden (cross-browser page exit signal).
// Embedded in the plugin via go:embed.
(function(){
  var t=Date.now(),v=0,s=0,c=0,k=0,sent=0;
  document.addEventListener('visibilitychange',function(){
    if(document.hidden){
      v+=Date.now()-t;
      if(!sent){sent=1;navigator.sendBeacon('/.well-known/policy-challenge/session',
        JSON.stringify([{ts:Date.now(),path:location.pathname,type:'pm',
          vis:v,scr:s,clk:c,key:k}]));}
    }else{t=Date.now();sent=0;}
  });
  window.addEventListener('scroll',function(){
    var p=Math.round((window.scrollY+window.innerHeight)/
      document.documentElement.scrollHeight*100);
    if(p>s)s=p;
  });
  document.addEventListener('click',function(){c++;});
  document.addEventListener('keydown',function(){k=1;},{once:true});
})();
