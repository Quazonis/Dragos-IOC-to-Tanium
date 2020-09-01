# Collection of scripts to allow communication to the Dragos API and Tanium API
#### Nathaniel Nieuwendam

* Dragos_IOCs_Sweep.ps1
	* This will retrieve MD5 and SHA256 hashes for all Dragos releases as far day as you specify in days (Default 60)
	* Script will attempt to retrieve meta data and converted IOC to Tanium QuickAdd Json objects.
	* Script will attempt to upload all IOCs associated with a Dragos release(Product)
	* IOCs not associated with a product will be grouped by last seen time
	* After uploads are complete, script will call intelIDQuickScanAuto.ps1 to begin quick scans operations
* intelIDQuickScanAuto.ps1
	* Optional addition. This script will attempt to take a passed array of intel ID and scan them against a static list of computer groups
	* Computer group ID MUST be configured before hand
	* Pass list of Intel ID using -param -intelIdArray
	* Script will verify each scan before moving to the next and return question id
