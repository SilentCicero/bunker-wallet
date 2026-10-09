import{expect,test}from"bun:test";
import{activityDetail,activityLink,type Activity}from"./activity";
const hash=`0x${"ab".repeat(32)}`;
test("links a rotation to Sepolia Etherscan with atomic-operation copy",()=>{const item:Activity={label:"Sent",hash,kind:"rotation",index:1};expect(activityLink(item)).toEqual({href:`https://sepolia.etherscan.io/tx/${hash}`,target:"_blank",rel:"noreferrer"});expect(activityDetail(item)).toBe("Sends ETH and advances the Safe owner atomically.")});
test("labels deployment links without claiming a send or rotation",()=>{const item:Activity={label:"Created",hash,kind:"deployment",index:0};expect(activityDetail(item)).toBe("Creates the Safe proxy; it does not send ETH or rotate the owner.")});
test("leaves simulated history unlinked",()=>{const item:Activity={label:"Preview",index:0};expect(activityLink(item)).toBeUndefined()});
