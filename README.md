# APT_Dataset_Creator

This Python3 script extracts all hashes (sha256, sha1, and md5) from [APT_CyberCriminal_Campagin_Collections](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections) PDF reports and creates an `output_YYYY-MM-DD.json` file. 
For more information on file structure, [here](https://github.com/packmad/APT_Dataset_Creator/blob/main/output_2021-08-16.json) you can find the latest run.

Moreover, during its execution, it also extracts all the archives it finds with well-known passwords.

The hashes can be used to download missing the samples from VirusTotal, while the extracted files can be organized as desired (I use my [PyPEfilter](https://github.com/packmad/pypefilter)).


### Dependencies
```
sudo apt install p7zip-full
```


### Clone (memento submodule)

```
git clone  <PROTO>packmad/APT_Dataset_Creator
cd APT_Dataset_Creator/
git submodule update --init --recursive
```

Get yourself some coffee because it's going to take a long time...

### Update
```
git pull
git submodule foreach git pull origin master
```



## Publications

Using this script, we created datasets for the following papers:

* [Prevalence and impact of low-entropy packing schemes in the malware ecosystem](https://simoneaonzo.it/assets/pdf/Prevalence_and_Impact_of_Low-Entropy_Packing_Schemes_in_the_Malware_Ecosystem.pdf)
```BibTeX
@inproceedings{mantovani2020prevalence,
  title={Prevalence and Impact of Low-Entropy Packing Schemes in the Malware Ecosystem},
  author={Mantovani, Alessandro and Aonzo, Simone and Ugarte-Pedrero, Xabier and Merlo, Alessio and Balzarotti, Davide},
  booktitle={Network and Distributed System Security (NDSS) Symposium, NDSS},
  volume={20},
  year={2020}
}
```

* Under submission #1
* Under submission #2
