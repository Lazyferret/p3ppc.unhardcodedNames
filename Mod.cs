using p3ppc.unhardcodedNames.Configuration;
using p3ppc.unhardcodedNames.Template;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;
using Reloaded.Hooks.Definitions.X64;
using Reloaded.Hooks.ReloadedII.Interfaces;
using Reloaded.Memory;
using Reloaded.Mod.Interfaces;
using Reloaded.Mod.Interfaces.Internal;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using IReloadedHooks = Reloaded.Hooks.ReloadedII.Interfaces.IReloadedHooks;

namespace p3ppc.unhardcodedNames;
/// <summary>
/// Your mod logic goes here.
/// </summary>
public unsafe class Mod : ModBase // <= Do not Remove.
{
    /// <summary>
    /// Provides access to the mod loader API.
    /// </summary>
    private readonly IModLoader _modLoader;

    /// <summary>
    /// Provides access to the Reloaded.Hooks API.
    /// </summary>
    /// <remarks>This is null if you remove dependency on Reloaded.SharedLib.Hooks in your mod.</remarks>
    private readonly IReloadedHooks? _hooks;

    /// <summary>
    /// Provides access to the Reloaded logger.
    /// </summary>
    private readonly ILogger _logger;

    /// <summary>
    /// Entry point into the mod, instance that created this class.
    /// </summary>
    private readonly IMod _owner;

    /// <summary>
    /// Provides access to this mod's configuration.
    /// </summary>
    private Config _configuration;

    /// <summary>
    /// The configuration of the currently executing mod.
    /// </summary>
    private readonly IModConfig _modConfig;

    private Memory _memory;

    private IHook<GetNameDelegate> _getItemNameHook;
    private IHook<GetNameDelegate> _getPersonaNameHook;
    private IHook<GetNameDelegate> _getCharacterFullNameHook;
    private IHook<GetNameDelegate> _getCharacterFirstNameHook;
    private IHook<GetNameDelegate> _getSLinkNameHook;
    private IHook<GetNameDelegate> _getSkillNameHook;
    private IHook<GetTextDelegate> _getTextHook;
    private IHook<GetEnemyNameDelegate> _getEnemyNameHook;

    private IAsmHook _analysisEnemyNameHook;
    private IReverseWrapper<GetNameDelegate> _getEnemyNameReverseWrapper;

    private IAsmHook _battleSkillSelectionNameHook;
    private IAsmHook _battleSkillPopupNameHook;
    private IReverseWrapper<GetNameDelegate> _getSkillNameReverseWrapper;

    private Dictionary<int, nuint[]> _itemNames = new();
    private Dictionary<int, nuint[]> _personaNames = new();
    private Dictionary<int, nuint[]> _characterFullNames = new();
    private Dictionary<int, nuint[]> _characterFirstNames = new();
    private Dictionary<int, nuint[]> _characterLastNames = new();
    private Dictionary<int, nuint[]> _sLinkNames = new();
    private Dictionary<int, nuint[]> _arcanaNames = new();
    private Dictionary<int, nuint[]> _enemyNames = new();
    private Dictionary<int, nuint[]> _skillNames = new();
    private Language* _language;

    public Mod(ModContext context)
    {
        _modLoader = context.ModLoader;
        _hooks = context.Hooks;
        _logger = context.Logger;
        _owner = context.Owner;
        _configuration = context.Configuration;
        _modConfig = context.ModConfig;
        _memory = Memory.Instance;

        if (!Utils.Initialise(_logger, _configuration, _modLoader))
            return;

        Utils.SigScan("E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 0F B6 84 ?? ?? ?? ?? ??", "GetItemName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 1);
            Utils.LogDebug($"Found GetItemName function at 0x{funcAddress:X}");
            _getItemNameHook = _hooks.CreateHook<GetNameDelegate>(GetItemName, (long)funcAddress).Activate();
        });

        Utils.SigScan("E9 ?? ?? ?? ?? 33 C0 48 83 C4 20 5B C3 8B 05 ?? ?? ?? ??", "GetPersonaName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 1);
            Utils.LogDebug($"Found GetPersonaName function at 0x{funcAddress:X}");
            _getPersonaNameHook = _hooks.CreateHook<GetNameDelegate>(GetPersonaName, (long)funcAddress).Activate();
        });

        Utils.SigScan("E8 ?? ?? ?? ?? F3 0F 10 0D ?? ?? ?? ?? 8B CF", "GetCharacterFullName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 1);
            Utils.LogDebug($"Found GetCharacterFullName function at 0x{funcAddress:X}");
            _getCharacterFullNameHook = _hooks.CreateHook<GetNameDelegate>(GetCharacterFullName, (long)funcAddress).Activate();
        });

        Utils.SigScan("0F 88 ?? ?? ?? ?? 41 51 48 89 14 24", "GetCharacterFirstName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 2);
            Utils.LogDebug($"Found GetCharacterFirstName function at 0x{funcAddress:X}");
            _getCharacterFirstNameHook = _hooks.CreateHook<GetNameDelegate>(GetCharacterFirstName, (long)funcAddress).Activate();
        });

        // TODO find GetCharacterLastName if it even exists (last names don't really seem to be used)
        //Utils.SigScan("E8 ?? ?? ?? ?? EB ?? F3 0F 10 BC 24 ?? ?? ?? ??", "GetCharacterLastName Ptr", address =>
        //{
        //    var funcAddress = Utils.GetGlobalAddress(address + 1);
        //    Utils.LogDebug($"Found GetCharacterLastName function at 0x{funcAddress:X}");
        //    _getCharacterLastNameHook = _hooks.CreateHook<GetNameDelegate>(GetCharacterLastName, (long)funcAddress).Activate();
        //});

        Utils.SigScan("E8 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 F3 41 0F 58 F0", "GetSkillName Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 1);
            Utils.LogDebug($"Found GetSkillName function at 0x{funcAddress:X}");
            _getSkillNameHook = _hooks.CreateHook<GetNameDelegate>(GetSkillName, (long)funcAddress).Activate();
        });

        Utils.SigScan("48 89 5C 24 ?? 57 48 83 EC 20 0F B7 D9 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 3B 5F ?? 72 ?? 8B 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 83 C2 02 E8 ?? ?? ?? ?? C1 E3 06 48 83 C7 08 89 D8", "GetSLinkName", address =>
        {
            _getSLinkNameHook = _hooks.CreateHook<GetNameDelegate>(GetSLinkName, address).Activate();
        });

        Utils.SigScan("40 53 48 83 EC 20 48 89 CB 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 8B ?? ?? ?? ??", "GetEnemyName", address =>
        {
            _getEnemyNameHook = _hooks.CreateHook<GetEnemyNameDelegate>(GetEnemyName, address).Activate();
        });

        Utils.SigScan("C7 44 24 ?? 00 00 00 00 41 B9 FF FF DF 69", "AnalysisGetEnemyName", address =>
        {
            string[] function =
            {
                "use64",
                "push rax \npush rcx",
                "mov rcx, r12", // Put enemy id into arg 1
                "sub rsp, 32",
                $"{_hooks.Utilities.GetAbsoluteCallMnemonics(AnalysisGetEnemyName, out _getEnemyNameReverseWrapper)}",
                "add rsp, 32",
                "pop rcx",
                "cmp rax, 0", 
                "je noChange",
                "add rsp, 8", // "pop" rax without actually putting it anywhere
                "jmp endHook",
                "label noChange",
                "pop rax",
                "label endHook",
            };

            _analysisEnemyNameHook = _hooks.CreateAsmHook(function, address, AsmHookBehaviour.ExecuteFirst).Activate();
        });

        var battleGetSkillName = _hooks.Utilities.GetAbsoluteCallMnemonics(BattleGetSkillName, out _getSkillNameReverseWrapper);

        Utils.SigScan("F3 44 0F 10 15 ?? ?? ?? ?? 33 C0", "BattleSkillSelectionName", address =>
        {
            string[] function =
            {
                "use64",
                "push rax \npush rcx",
                "mov rcx, rdi", // Put skill id into first arg
                "sub rsp, 32",
                $"{battleGetSkillName}",
                "add rsp, 32",
                "pop rcx",
                "cmp rax, 0",
                "je endHook",
                "mov rcx, rax",
                "label endHook",
                "pop rax",
            };

            _battleSkillSelectionNameHook = _hooks.CreateAsmHook(function, address, AsmHookBehaviour.ExecuteFirst).Activate();
        });

        Utils.SigScan("E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8B 89 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? F3 0F 59 05 ?? ?? ?? ?? F3 0F 58 43 ?? 0F 2F 05 ?? ?? ?? ?? F3 0F 11 43 ?? 73 ?? 31 C0", "BattleSkillPopupName", address =>
        {
            string[] function =
            {
                "use64",
                "push rcx \npush rdx",
                "mov rcx, rax", // Put skill id into first arg
                "sub rsp, 32",
                $"{battleGetSkillName}",
                "add rsp, 32",
                "pop rdx \npop rcx",
                "cmp rax, 0",
                "je endHook",
                "mov rdx, rax",
                "label endHook",
            };

            _battleSkillPopupNameHook = _hooks.CreateAsmHook(function, address, AsmHookBehaviour.ExecuteFirst).Activate();
        });


        Utils.SigScan("E8 ?? ?? ?? ?? F3 44 0F 10 3D ?? ?? ?? ?? F3 41 0F 5C F5", "GetHardcodedText Ptr", address =>
        {
            var funcAddress = Utils.GetGlobalAddress(address + 1);
            Utils.LogDebug($"Found GetHardcodedText function at 0x{funcAddress:X}");
            _getTextHook = _hooks.CreateHook<GetTextDelegate>(GetText, (long)funcAddress).Activate();
        });

        Utils.SigScan("48 63 05 ?? ?? ?? ?? 0F 57 F6", "LanguagePtr", address =>
        {
            var languageAddress = Utils.GetGlobalAddress(address + 3);
            Utils.LogDebug($"Found Language at 0x{languageAddress:X}");
            _language = (Language*)languageAddress;
        });

        _modLoader.ModLoading += OnModLoading;

        foreach (var mod in _modLoader.GetActiveMods().Where(x => x.Generic.ModDependencies.Contains(_modConfig.ModIcon)))
            AddNamesFromDir(_modLoader.GetDirectoryForModId(mod.Generic.ModId));
    }

    private void OnModLoading(IModV1 mod, IModConfigV1 config)
    {
        if (config.ModDependencies.Contains(_modConfig.ModId))
            AddNamesFromDir(_modLoader.GetDirectoryForModId(config.ModId));
    }

    private void AddNamesFromDir(string dir)
    {
        AddNamesFromDir<Name,string?>(dir, _itemNames, "ItemNames.json", WriteGenericName);
        AddNamesFromDir<Name,string?>(dir, _personaNames, "PersonaNames.json", WriteGenericName);
        AddNamesFromDir<Name,string?>(dir, _sLinkNames, "SLinkNames.json", WriteGenericName);
        AddNamesFromDir<Name,string?>(dir, _arcanaNames, "ArcanaNames.json", WriteGenericName);
        AddNamesFromDir<Name,string?>(dir, _enemyNames, "EnemyNames.json", WriteGenericName);
        AddNamesFromDir<Name,string?>(dir, _skillNames, "SkillNames.json", WriteGenericName);
        AddNamesFromDir<CharacterName,NameParts?>(dir, _characterFullNames, "CharacterNames.json", WriteCharacterName);
    }

    private void AddNamesFromDir<T1,T2>(string dir, Dictionary<int, nuint[]> namesDict, string nameFile, Action<object, Dictionary<int, nuint[]>, int, int> WriteName)
        where T1 : IName<T2>
    {
        var namesPath = Path.Combine(dir, nameFile);
        if (!File.Exists(namesPath)) return;

        var json = File.ReadAllText(namesPath);
        var names = JsonSerializer.Deserialize<List<T1>>(json);
        if (names == null)
        {
            Utils.LogError($"Error parsing names from {namesPath}");
            return;
        }

        foreach (var name in names)
        {
            var id = name.Id;
            var languages = Enum.GetNames(typeof(Language));

            if (!namesDict.ContainsKey(id))
                namesDict[id] = new nuint[languages.Length];

            for (int i = 0; i < languages.Length; i++)
            {
                var langName = name.GetType().GetProperty(languages[i]).GetValue(name);
                if (langName == null && name.All != null)
                    langName = name.All;
                if (langName != null)
                {
                    WriteName(langName, namesDict, id, i);
                }
            }
        }
    }

    private void WriteGenericName(object langName, Dictionary<int, nuint[]> namesDict, int id, int lang)
    {
        var address = WriteString((string)langName);
        namesDict[id][lang] = address;
    }

    private void WriteCharacterName(object langName, Dictionary<int, nuint[]> namesDict, int id, int lang)
    {
        var name = (NameParts)langName;
        if (name.First != null)
        {
            if (!_characterFirstNames.ContainsKey(id))
                _characterFirstNames[id] = new nuint[9];

            var address = WriteString(name.First);
            _characterFirstNames[id][lang] = address;
        }

        if (name.Last != null)
        {
            if (!_characterLastNames.ContainsKey(id))
                _characterLastNames[id] = new nuint[9];

            var address = WriteString(name.Last);
            _characterLastNames[id][lang] = address;
        }

        var fullName = name.Full;
        if(fullName == null)
            fullName = $"{(name.First == null ? "" : name.First)} {(name.Last == null ? "" : name.Last)}";

        var fullAddress = WriteString(fullName);
        _characterFullNames[id][lang] = fullAddress;

    }

    private nuint WriteString(string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        var address = _memory.Allocate((nuint)bytes.Length).Address;
        _memory.WriteRaw(address, bytes);
        return address;
    }

    private nuint GetItemName(short item)
    {
        if (!_itemNames.TryGetValue(item, out var name))
        {
            return _getItemNameHook.OriginalFunction(item);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getItemNameHook.OriginalFunction(item);

        return langName;
    }

    private nuint GetPersonaName(short persona)
    {
        if (!_personaNames.TryGetValue(persona, out var name))
        {
            return _getPersonaNameHook.OriginalFunction(persona);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getPersonaNameHook.OriginalFunction(persona);

        return langName;
    }

    private nuint GetCharacterFullName(short character)
    {
        if (!_characterFullNames.TryGetValue(character, out var name))
        {
            return _getCharacterFullNameHook.OriginalFunction(character);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getCharacterFullNameHook.OriginalFunction(character);

        return langName;
    }

    private nuint GetCharacterFirstName(short character)
    {
        if (!_characterFirstNames.TryGetValue(character, out var name))
        {
            return _getCharacterFirstNameHook.OriginalFunction(character);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getCharacterFirstNameHook.OriginalFunction(character);

        return langName;
    }

    private nuint GetSLinkName(short sLink)
    {
        if (!_sLinkNames.TryGetValue(sLink, out var name))
        {
            return _getSLinkNameHook.OriginalFunction(sLink);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getSLinkNameHook.OriginalFunction(sLink);

        return langName;
    }

    private nuint GetSkillName(short id)
    {
        if (!_skillNames.TryGetValue(id, out var name))
        {
            return _getSkillNameHook.OriginalFunction(id);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getSkillNameHook.OriginalFunction(id);

        return langName;
    }

    private nuint GetText(NameType type, short id)
    {
        if (type != NameType.Arcana || !_arcanaNames.TryGetValue(id, out var name))
        {
            return _getTextHook.OriginalFunction(type, id);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getTextHook.OriginalFunction(type, id);

        return langName;
    }

    private nuint GetEnemyName(EnemyInfo* info)
    {
        var id = info->Id;
        if (!_enemyNames.TryGetValue(id, out var name))
        {
            return _getEnemyNameHook.OriginalFunction(info);
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return _getEnemyNameHook.OriginalFunction(info);

        return langName;
    }

    private nuint AnalysisGetEnemyName(short id)
    {
        if (!_enemyNames.TryGetValue(id, out var name))
        {
            return 0;
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return 0;

        return langName;
    }

    private nuint BattleGetSkillName(short id)
    {
        if (!_skillNames.TryGetValue(id, out var name))
        {
            return 0;
        }

        var langName = name[(int)*_language];
        if (langName == nuint.Zero)
            return 0;

        return langName;
    }


    [Function(CallingConventions.Microsoft)]
    private delegate nuint GetNameDelegate(short id);

    [Function(CallingConventions.Microsoft)]
    private delegate nuint GetEnemyNameDelegate(EnemyInfo* info);

    [Function(CallingConventions.Microsoft)]
    private delegate nuint GetTextDelegate(NameType type, short id);

    private enum NameType : int
    {
        Arcana = 9,
    }

    private enum Language : int
    {
        Japanese,
        English,
        Korean,
        TraditionalChinese,
        SimplifiedChinese,
        French,
        German,
        Italian,
        Spanish
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct EnemyInfo
    {
        [FieldOffset(164)]
        internal short Id;
    }

    #region Standard Overrides
    public override void ConfigurationUpdated(Config configuration)
    {
        // Apply settings from configuration.
        // ... your code here.
        _configuration = configuration;
        _logger.WriteLine($"[{_modConfig.ModId}] Config Updated: Applying");
    }
    #endregion

    #region For Exports, Serialization etc.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    public Mod() { }
#pragma warning restore CS8618
    #endregion
}