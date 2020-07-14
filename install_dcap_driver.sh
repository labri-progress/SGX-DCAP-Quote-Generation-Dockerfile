#!/usr/bin/env bash

# Originates from https://github.com/Azure/aks-engine/blob/v0.52.0/parts/k8s/cloud-init/artifacts/cse_config.sh

# MIT License
#
# Copyright (c) 2016 Microsoft Azure
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


if test $(id -u) -ne 0; then
  echo "Root privilege is required."
    exit 1
fi

install_dir=installdriver
mkdir $install_dir
cd $install_dir

UBUNTU_RELEASE1=$(grep VERSION_ID /etc/os-release | cut -d '=' -f2)
UBUNTU_RELEASE=${UBUNTU_RELEASE1:1:-1}

apt-get -y install make gcc dkms
curl -fsSL -O "https://download.01.org/intel-sgx/latest/version.xml"

dcap_version="$(grep dcap version.xml | grep -o -E "[.0-9]+")"
sgx_driver_folder_url="https://download.01.org/intel-sgx/sgx-dcap/$dcap_version/linux"
curl -fsSL -O "$sgx_driver_folder_url/SHA256SUM_dcap_$dcap_version.cfg"
matched_line="$(grep "distro/ubuntu$UBUNTU_RELEASE-server/sgx_linux_x64_driver_.*bin" SHA256SUM_dcap_$dcap_version.cfg)"
read -ra tmp_array <<<"$matched_line"
sgx_driver_sha256sum_expected="${tmp_array[0]}"
sgx_driver_remote_path="${tmp_array[1]}"
sgx_driver_url="${sgx_driver_folder_url}/${sgx_driver_remote_path}"
sgx_driver=$(basename "$sgx_driver_url")

curl -fsSL -O "${sgx_driver_url}"
read -ra tmp_array <<<"$(sha256sum ./"$sgx_driver")"
sgx_driver_sha256sum_real="${tmp_array[0]}"
[[ $sgx_driver_sha256sum_real == "$sgx_driver_sha256sum_expected" ]] || exit 93

chmod a+x ./"${sgx_driver}"
if ! ./"${sgx_driver}"; then
  cd ..
  rm -r $install_dir
  exit 0
fi

cd ..
rm $install_dir -r
