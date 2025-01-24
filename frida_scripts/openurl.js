function openURL(storelink) {
	const UIApplication = ObjC.classes.UIApplication.sharedApplication()
	const toOpen = ObjC.classes.NSURL.URLWithString_(storelink)
	return UIApplication.openURL_(toOpen)
};
rpc.exports = {
	openurl: function (storelink) {
		openURL(storelink);
		return '[*] Opened appstore at: ' + storelink;
	},
	failPlease: function () {
		oops;
	}
};