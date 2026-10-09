import{activityDetail,activityLink,type Activity}from"./activity";
const short=(value:string)=>`${value.slice(0,8)}…${value.slice(-6)}`;
export function HistoryEntry(props:{item:Activity;rotation:number}){
 const body=<><span>{props.item.index===props.rotation?"Latest":"Done"}</span><p><b>{props.item.label}</b><small>{activityDetail(props.item)}</small>{props.item.usedSigner&&<code>Used signer · {short(props.item.usedSigner)}</code>}</p><small>{props.item.hash?"View transaction ↗":"Preview"}</small></>;
 const link=activityLink(props.item);
 return link?<a class="activity-row activity-link" href={link.href} target={link.target} rel={link.rel} aria-label={`${props.item.label} on Sepolia Etherscan`}>{body}</a>:<div class="activity-row">{body}</div>;
}
