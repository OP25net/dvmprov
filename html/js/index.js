/*******************************************************
 * Cookie Functions & Variables
 *******************************************************/

var config = {
    lastPage: null
}

function loadConfig() {
    if (!localStorage.getItem("config")) {
        console.warn("No local storage settings found, using defaults");
        localStorage.setItem("config", JSON.stringify(config));
    } else {
        config = JSON.parse(localStorage.getItem("config"));
        console.log("Loaded save config");
    }
}

function saveConfig() {
    localStorage.setItem("config", JSON.stringify(config));
    console.log("Saved config");
}

function clearConfig() {
    localStorage.clear();
    console.warn("Removed all local storage settings");
}

/*******************************************************
 * Global Variables/Constants
 *******************************************************/

const spinnerSmall = document.getElementById("spinner-small");

/*******************************************************
 * Global Functions
 *******************************************************/

function enableTooltips() {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerE1 => new bootstrap.Tooltip(tooltipTriggerE1));
}

/*******************************************************
 * FNE Communication Functions
 *******************************************************/

function connectFne() {
    console.log(`Connecting to FNE at address ${config.fneAddress}`);
}

/*******************************************************
 * Sidebar Navigation Buttons
 *******************************************************/

function page(obj) {
    // Remove active from the side navbar items
    $("#nav-side .nav-link").removeClass("active");
    // Hide all other pages and show the selected page
    $(".page").fadeOut(150).promise().done(function() {
        if (obj.dataset.page) {
            $(`#${obj.dataset.page}`).fadeIn(150);
        }
    });
    // Make the current button active and hide the tooltip
    $(obj).addClass("active");
    $(obj).tooltip('hide');
}

/*******************************************************
 * Table Sorting Functions
 * https://stackoverflow.com/a/19947532/1842613
 *******************************************************/

function clearSort(table) {
    // Remove the sort property
    table.find('th').attr({
        "data-sort": "none"
    });
    // Reset sort
    table.find('th i').removeClass().addClass("iconoir-sort unsorted");
}

function clickSort(header) {
    // Get the table
    var table = $(header).parents('table').eq(0);
    // Set sort mode
    if (header.dataset.sort == "asc") {
        clearSort(table);
        header.dataset.sort = "desc";
    }
    else {
        clearSort(table);
        header.dataset.sort = "asc";
    }
    // Sort
    sortTable(table, header);
}

function sortTable(table, header) {
    // Sort rows
    var rows = $(table).find('tr:gt(0)').toArray().sort(comparer($(header).index()))

    // Set sort icon
    if (header.dataset.sort == "asc") {
        $(header).find("i").removeClass("iconoir-sort unsorted").addClass("iconoir-sort-up");
    }
    else {
        $(header).find("i").removeClass("iconoir-sort unsorted").addClass("iconoir-sort-down");
    }
    
    // Reorder depending on mode
    if (header.dataset.sort == "desc") {
        rows = rows.reverse()
    }

    // Add the new rows
    for (var i = 0; i < rows.length; i++) {
        table.append(rows[i])
    }
}

function comparer(index) {
    return function(a, b) {
        var valA = getCellValue(a, index), valB = getCellValue(b, index);
        return $.isNumeric(valA) && $.isNumeric(valB) ? valA - valB : valA.toString().localeCompare(valB);
    }
}

function getCellValue(row, index) {
    return $(row).children('td').eq(index).html();
}

/*******************************************************
 * RID Management Page Functions
 *******************************************************/

const ridTable = $("#ut-body");
const ridRowTemplate = $("#utr-template");

// Add table row for RID
function addRidToTable(rid, enabled, alias) {
    const newRow = $(ridRowTemplate.html());
    newRow.find('.ut-rid').html(rid);
    newRow.find('.ut-alias').html(alias);
    //tds[1].textContent = callsign;
    //tds[2].textContent = operator;
    if (enabled)
    {
        newRow.find('.ut-enabled').html('<i class="iconoir-check-circle-solid"></i>');
        newRow.find('.ut-enabled').addClass('text-success');
    }
    else
    {
        newRow.find('.ut-enabled').html('<i class="iconoir-xmark-circle-solid"></i>');
        newRow.find('.ut-enabled').addClass('text-danger');
    }

    ridRowTemplate.before(newRow);

    // Enable the tooltips on the buttons
    enableTooltips();
}

function updateRidTable() {
    // Clear table
    $("#ut-body tr").remove();
    // Show loading spinner
    $("#spinnerTable").show();
    // Query
    $.ajax({
        type: "GET",
        dataType: "json",
        url: "php/ridGet.php",
        success: function (data) {
            console.log("Got new rid data")
            data.rids.forEach(entry => {
                addRidToTable(entry.id, entry.enabled, entry.alias);
            });
            // Hide the loading spinner
            $("#ridSpinnerTable").hide();
            // Sort
            const table = $("#ut");
            const header = document.querySelectorAll("#ut th")[0];
            sortTable(table, header);
        }
    })
}

/**
 * Checks if the given RID is present in the RID table
 * @param {int} rid radio ID to check
 * @returns true if the RID is in the table
 */
function checkIfRIDExists(rid) {
    if ( $(`#ut-body tr > td:contains(${rid})`).length > 0 )
    {
        return true
    }
    else
    {
        return false
    }
}

function clearRidForm() {
    // Blank the values
    $("#addRidFormRID").val("");
    $("#addRidFormAlias").val("");
    $("#addRidFormEnabled").prop("checked", false);
    // Reset invalid classes
    $("#addRidFormRID").removeClass("is-invalid");
    $("#addRidFormAlias").removeClass("is-invalid");
    // Reset valid classes
    $("#addRidFormRID").removeClass("is-valid");
    $("#addRidFormAlias").removeClass("is-valid");
    // Enable the RID if disabled
    $("#addRidFormRID").prop("disabled", false);
}

function ridFormSuccess() {
    // Clear any invalids
    $("#addRidFormRID").removeClass("is-invalid");
    $("#addRidFormAlias").removeClass("is-invalid");
    // Make everything valid
    $("#addRidFormRID").addClass("is-valid");
    $("#addRidFormAlias").addClass("is-valid");
    setTimeout(() => {
        updateRidTable();
        $("#modalRidAdd").modal('hide');
        clearRidForm();
    }, 1000);
}

function addRidForm() {
    // Get values from form
    const newRID = parseInt($("#addRidFormRID").val());
    const newAlias = $("#addRidFormAlias").val();
    const enabled = $("#addRidFormEnabled").prop("checked");

    postData = {
        rid: newRID,
        alias: newAlias,
        enabled: enabled,
    }

    // Send the data and verify success
    $.post("php/ridAdd.php",
    postData,
    function(data, status) {
        switch (data.status)
        {
            case 200:
                // Clear & close the form
                console.log("Successfully added new RID!");
                ridFormSuccess();
                break;
            default:
                console.error("Failed to add RID: " + data.status);
                break;
        }
    });
    
}

function ridPromptEdit(element) {
    // Get the parameters from the table
    const editRid = $(element).closest("tr").find(".ut-rid").text();
    const editAlias = $(element).closest("tr").find(".ut-alias").text();
    const editEnabled = (($(element).closest("tr").find(".ut-enabled").html().includes("checkmark-circle-sharp")) ? true : false);
    // Populate the edit modal
    $("#addRidFormRID").val(editRid);
    $("#addRidFormAlias").val(editAlias);
    $("#addRidFormEnabled").prop("checked", editEnabled);
    // Disable RID edit
    $("#addRidFormRID").prop("disabled", true);
    // Show
    $("#modalRidAdd").modal('show');
}

function ridPromptDelete(element) {
    const delRid = $(element).closest("tr").find(".ut-rid").text();
    const delAlias = $(element).closest("tr").find(".ut-alias").text();
    // Update the delete modal text
    $("#modalRidDelete").find(".modal-body").html(`Delete RID ${delRid} (${delAlias})?`);
    // Update the delete function onclick
    $("#modalRidDelete").find(".btn-danger").click(() => {
        deleteRid(delRid);
    });

    // Show the modal
    $("#modalRidDelete").modal('show');
}

function cancelRidDelete() {
    $("#modalRidDelete").find(".modal-body").html('');
    $("#modalRidDelete").find(".btn-danger").prop('onclick', null).off('click');
}

/**
 * Delete the specified RID from the table
 * @param {int} delRid RID to delete
 */
function deleteRid(delRid) {
    $.post("php/ridDel.php",
    {
        rid: parseInt(delRid)
    },
    function (data, status) {
        if (data.status == 200) {
            console.log(`Successfully deleted RID ${delRid}`);
            $("#modalRidDelete").modal('hide');
            updateRidTable();
        } else {
            console.error("Failed to delete RID: " + data);
            alert("Failed to delete RID");
        }
    });
}

/*******************************************************
 * TG Management Page Functions
 *******************************************************/

const tgTable = $("#tgt-body");
const tgRowTemplate = $("#tgtr-template");

// Add table row for TG
function addTgToTable(tgid, slot, name, active, affiliated) {
    const newRow = $(tgRowTemplate.html());
    newRow.find('.tgt-tgid').html(tgid);
    newRow.find('.tgt-slot').html(slot);
    newRow.find('.tgt-name').html(name);
    // Active Checkmark
    if (active)
    {
        newRow.find('.tgt-active').html('<i class="iconoir-check-circle-solid"></i>');
        newRow.find('.tgt-active').addClass('text-success');
    }
    else
    {
        newRow.find('.tgt-active').html('<i class="iconoir-xmark-circle-solid"></i>');
        newRow.find('.tgt-active').addClass('text-danger');
    }
    // Affiliated Checkmark
    if (affiliated)
    {
        newRow.find('.tgt-affiliated').html('<i class="iconoir-check-circle-solid"></i>');
        newRow.find('.tgt-affiliated').addClass('text-primary');
    }
    else
    {
        newRow.find('.tgt-affiliated').html('<i class="iconoir-xmark-circle-solid"></i>');
        newRow.find('.tgt-affiliated').addClass('text-secondary');
    }

    tgRowTemplate.before(newRow);

    // Enable the tooltips on the buttons
    enableTooltips();
}

function updateTgTable() {
    // Clear table
    $("#tgt-body tr").remove();
    // Show loading spinner
    $("#spinnerTable").show();
    // Query
    $.ajax({
        type: "GET",
        dataType: "json",
        url: "php/tgGet.php",
        success: function (data) {
            console.log("Got new TG data")
            data.tgs.forEach(entry => {
                addTgToTable(entry.source.tgid, entry.source.slot, entry.name, entry.config.active, entry.config.affiliated);
            });
            // Hide the loading spinner
            $("#tgSpinnerTable").hide();
            // Sort
            var table = $("#tgt");
            var header = document.querySelectorAll("#tgt th")[0];
            sortTable(table, header);
        }
    })
}

function getTgInfo(tgid, slot) {
    // Show loading spinner
    $("#tgSpinnerInfo").show();
    // Query list of tgs
    $.ajax({
        type: "GET",
        dataType: "json",
        url: "php/tgGet.php",
        success: function (data) {
            data.tgs.forEach(entry => {
                // Find the TGID we're looking for
                if (Number(entry.source.tgid) == Number(tgid) && Number(entry.source.slot) == Number(slot)) {
                    // Populate the tg info box
                    $("#tgInfoBox").html(JSON.stringify(entry, null, 2));
                    // Hide the spinner
                    $("#tgSpinnerInfo").hide();
                } 
            });
        }
    })
}

function clearTgInfo() {
    $("#tgInfoBox").html("");
}

function tgPromptDelete(element) {
    const delTgid = $(element).closest("tr").find(".tgt-tgid").text();
    const delName = $(element).closest("tr").find(".tgt-name").text();
    // Update the delete modal text
    $("#modalTgDelete").find(".modal-body").html(`Delete TGID ${delTgid} (${delName})?`);
    // Update the delete function onclick
    $("#modalTgDelete").find(".btn-danger").click(() => {
        deleteTg(delTgid);
    });

    // Show the modal
    $("#modalTgDelete").modal('show');
}

function cancelTgDelete() {
    $("#modalTgDelete").find(".modal-body").html('');
    $("#modalTgDelete").find(".btn-danger").prop('onclick', null).off('click');
}

/**
 * Delete the specified RID from the table
 * @param {int} delTgid RID to delete
 */
function deleteTg(delTgid) {
    $.post("php/tgDel.php",
    {
        tgid: parseInt(delTgid)
    },
    function (data, status) {
        if (data.status == 200) {
            console.log(`Successfully deleted TGID ${delTgid}`);
            $("#modalTgDelete").modal('hide');
            updateTgTable();
        } else {
            console.error("Failed to delete TGID: " + data);
            alert("Failed to delete TGID");
        }
    });
}

function tgPromptInfo(element) {
    const infoTgid = $(element).closest("tr").find(".tgt-tgid").text();
    const infoSlot = $(element).closest("tr").find(".tgt-slot").text();
    const tgInfo = getTgInfo(parseInt(infoTgid), parseInt(infoSlot));
    // Show info modal
    $("#modalTgInfo").modal('show');
}

/*******************************************************
 * Window Onload
 *******************************************************/

window.onload = () => {
    // Init Tooltips
    enableTooltips();
    // Load config
    loadConfig();
    // Load initial data
    updateRidTable();
    updateTgTable();
}