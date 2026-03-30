// Page-level behavioral collector for session tracking.
// Injected as inline script into HTML responses when a valid challenge cookie
// is present. Tracks visible dwell time, scroll depth, and interaction events.
// Beacons data on visibilitychange→hidden (cross-browser page exit signal).
// Embedded in the plugin via go:embed.
(function(){
  var t=Date.now(),v=0,s=0,c=0,k=0,sent=0;
  // P2: Application-state verification (Option C).
  // If __pc_app_checks is defined (injected by plugin), check app state
  // on first load. Beacon failure if any required property/selector is missing.
  if(typeof __pc_app_checks!=='undefined'&&__pc_app_checks.length>0){
    var fails=[];
    for(var i=0;i<__pc_app_checks.length;i++){
      var ch=__pc_app_checks[i],ok=false;
      try{
        if(ch.type==='window_prop'){
          var parts=ch.path.split('.'),obj=window;
          for(var j=0;j<parts.length;j++){obj=obj[parts[j]];if(obj===undefined)break;}
          ok=obj!==undefined;
        }else if(ch.type==='dom_selector'){
          ok=!!document.querySelector(ch.selector);
        }else if(ch.type==='meta_content'){
          var el=document.querySelector('meta[name="'+ch.name+'"]');
          ok=el&&!!el.content;
        }
      }catch(e){}
      if(!ok)fails.push(ch.type+':'+(ch.path||ch.selector||ch.name));
    }
    if(fails.length>0){
      navigator.sendBeacon('/.well-known/policy-challenge/session',
        JSON.stringify([{ts:Date.now(),path:location.pathname,type:'app_state_fail',
          fails:fails}]));
    }
  }
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
