The `/game/refundShopItem` endpoint (`ShopService.refundShopItem`) performs a
check which queries the database to check if the player has the item being
refunded, followed by a short delay (artificially introduced for checking
proximity to the shop), followed by removing the item from the player and
updating the player's ball bearings amount. There is a race condition
vulnerability in this endpoint which allows a player to refund an item more
than once by calling the `/game/refundShopItem` endpoint multiple times in a
short time window. Repeating this adds a large amount of ball bearings to your
account, giving you enough to buy the flag and read its description!
