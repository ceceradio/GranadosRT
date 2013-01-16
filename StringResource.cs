using System;
using System.Globalization;
using System.Resources;
using System.Diagnostics;
using System.Reflection;
using Windows.ApplicationModel.Resources;

namespace GranadosRT.Routrek.SSHC {

	/// <summary>
	/// StringResource �̊T�v�̐����ł��B
	/// </summary>
	internal class StringResources {
		private string _resourceName;
		private ResourceLoader _resMan;

		public StringResources(string name, Assembly asm) {
			_resourceName = name;
			LoadResourceManager(name, asm);
		}

		public string GetString(string id) {
			return _resMan.GetString(id); //�������ꂪ�x���悤�Ȃ炱�̃N���X�ŃL���b�V���ł�����΂������낤
		}

		private void LoadResourceManager(string name, Assembly asm) {
			//���ʂ͉p��E���{�ꂵ�����Ȃ�
            _resMan = new Windows.ApplicationModel.Resources.ResourceLoader();
		}
	}
}