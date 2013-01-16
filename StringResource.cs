using System;
using System.Globalization;
using System.Resources;
using System.Diagnostics;
using System.Reflection;
using Windows.ApplicationModel.Resources;

namespace GranadosRT.Routrek.SSHC {

	/// <summary>
	/// StringResource の概要の説明です。
	/// </summary>
	internal class StringResources {
		private string _resourceName;
		private ResourceLoader _resMan;

		public StringResources(string name, Assembly asm) {
			_resourceName = name;
			LoadResourceManager(name, asm);
		}

		public string GetString(string id) {
			return _resMan.GetString(id); //もしこれが遅いようならこのクラスでキャッシュでもつくればいいだろう
		}

		private void LoadResourceManager(string name, Assembly asm) {
			//当面は英語・日本語しかしない
            _resMan = new Windows.ApplicationModel.Resources.ResourceLoader();
		}
	}
}