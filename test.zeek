@load base/frameworks/sumstats
global respall:count=0;
global resp404:count=0;
global URL:string;
event zeek_init()
    {
    local reducer = SumStats::Reducer($stream="code", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="code.unique",
                      $epoch=10mins,
                      $reducers=set(reducer),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r= result["code"];
						respall=r$num;
                        }]);
                        
                        
	local reducer1 = SumStats::Reducer($stream="404code", $apply=set(SumStats::UNIQUE));
	SumStats::create([$name="404code.unique",
                      $epoch=10mins,
                      $reducers=set(reducer1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
						local r = result["404code"];
						resp404=r$num;
                        }]);	
    local reducer2 = SumStats::Reducer($stream="url", $apply=set(SumStats::UNIQUE));
	SumStats::create([$name="url.unique",
                      $epoch=10mins,
                      $reducers=set(reducer2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
						local r = result["url"];
						if(resp404>2&& resp404/respall>0.2 && r$unique/resp404>0.5)
						{
							print fmt("%s is the orig_h, %d is the count og 404 code, %s is the unique count of url respomse 404.",key$host,resp404, 
                        		r$unique );	
						}
                        }]);
    }


event http_reply(c: connection, version: string, code: count, reason: string)
{
        SumStats::observe("code", SumStats::Key($host=c$id$orig_h), 
                      SumStats::Observation($num=1));
		if(code==404)
		{
			SumStats::observe("404code", SumStats::Key($host=c$id$orig_h), 
                      SumStats::Observation($num=1));
            SumStats::observe("url", SumStats::Key($str=URL), 
                      SumStats::Observation($num=1));
		}
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
	URL=original_URI;
}
