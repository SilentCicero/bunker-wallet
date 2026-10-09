export type Activity={label:string;hash?:string;kind?:"deployment"|"rotation";index:number;usedSigner?:string;activeSigner?:string};
export const activityDetail=(item:Activity)=>item.kind==="deployment"
  ?"Creates the Safe proxy; it does not send ETH or rotate the owner."
  :item.kind==="rotation"
    ?"Sends ETH and advances the Safe owner atomically."
    :item.usedSigner?`Key ${item.index} → Key ${item.index+1}`:`Key ${item.index+1} active`;
export const activityLink=(item:Activity)=>item.hash?{href:`https://sepolia.etherscan.io/tx/${item.hash}`,target:"_blank",rel:"noreferrer"}:undefined;
